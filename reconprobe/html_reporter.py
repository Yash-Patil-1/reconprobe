"""HTML report generator for ReconProbe.

Generates a standalone interactive HTML dashboard with Chart.js visualizations,
collapsible sections, and responsive dark-themed layout.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Optional

CHARTJS_CDN = "https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _status_color(code: int) -> str:
    """Return CSS color for HTTP status code."""
    if 200 <= code < 300:
        return "#22c55e"  # green
    elif 300 <= code < 400:
        return "#3b82f6"  # blue
    elif 400 <= code < 500:
        return "#f59e0b"  # amber
    else:
        return "#ef4444"  # red


def _severity_color(severity: str) -> str:
    """Return CSS color for CVE severity."""
    severity = severity.upper()
    if severity == "CRITICAL":
        return "#450a0a"
    elif severity == "HIGH":
        return "#dc2626"
    elif severity == "MEDIUM":
        return "#d97706"
    elif severity == "LOW":
        return "#ca8a04"
    return "#6b7280"


def _severity_badge_color(severity: str) -> str:
    """Return badge CSS for CVE severity."""
    severity = severity.upper()
    if severity == "CRITICAL":
        return "badge-critical"
    elif severity == "HIGH":
        return "badge-high"
    elif severity == "MEDIUM":
        return "badge-medium"
    elif severity == "LOW":
        return "badge-low"
    return "badge-none"


def generate_html_report(report: dict) -> str:
    """Generate a complete standalone HTML dashboard from a scan report."""
    target = report.get("target", {})
    scan_info = report.get("scan_info", {})
    sub_info = report.get("subdomain_enumeration", {})
    port_info = report.get("port_scanning", {})
    http_info = report.get("http_probing", {})
    enrichment_info = report.get("enrichment", {})
    crawl_info = report.get("crawling", {})
    dirbuster_info = report.get("dirbuster", {})
    screenshot_info = report.get("screenshots", {})
    # Phase 3 data
    vuln_info = report.get("vulnerability_scan", {})
    ssl_info = report.get("ssl_tls_audit", {})
    takeover_info = report.get("subdomain_takeover", {})
    waf_info = report.get("waf_detection", {})
    # Phase 4 data
    exploit_info = report.get("exploit_suggestions", {})
    payload_info = report.get("payloads", {})
    loot_info = report.get("loot", {})
    msf_info = report.get("msf_script", {})
    # Phase 5 data
    osint_info = report.get("osint", {})

    # Compute summary counts
    total_subdomains = sub_info.get("total_found", 0)
    total_resolved = sub_info.get("total_resolved", 0)
    total_open_ports = sum(h.get("open_ports", 0) for h in port_info.get("hosts", []))
    total_alive = http_info.get("total_alive_services", 0)

    shodan_results = enrichment_info.get("shodan", {}).get("results", {})
    cve_results_list = enrichment_info.get("cve_lookup", {}).get("results", [])
    total_cves = len(cve_results_list)
    high_critical_cves = sum(
        1 for c in cve_results_list if c.get("cvss_severity", "").upper() in ("HIGH", "CRITICAL")
    )

    total_crawled = crawl_info.get("total_pages_crawled", 0)
    total_crawl_findings = crawl_info.get("total_findings", 0)
    total_dirb_found = dirbuster_info.get("total_paths_found", 0)
    # Phase 3 summary counts
    total_vuln_cves = vuln_info.get("total_cves", 0)
    total_vuln_high = vuln_info.get("total_high_severity", 0)
    total_ssl_endpoints = len(ssl_info.get("results", {})) if ssl_info else 0
    total_takeover_vulns = takeover_info.get("total_vulnerable", 0)
    total_waf_protected = waf_info.get("total_protected", 0)
    # Phase 4 summary counts
    total_exploit_suggestions = exploit_info.get("total_suggestions", 0)
    total_payloads = payload_info.get("total_payloads", 0)
    total_loot_items = loot_info.get("total_count", 0)
    total_loot_critical = loot_info.get("critical_count", 0)
    total_msf_modules = msf_info.get("module_count", 0)
    total_osint_findings = osint_info.get("total_findings", 0)
    total_osint_critical = osint_info.get("severity_counts", {}).get("critical", 0)
    total_osint_high = osint_info.get("severity_counts", {}).get("high", 0)

    # Build chart data JSON
    chart_data = _build_chart_data(report)

    duration_str = ""
    if scan_info.get("duration_seconds"):
        d = scan_info["duration_seconds"]
        if d < 60:
            duration_str = f"{d:.1f}s"
        elif d < 3600:
            duration_str = f"{d / 60:.1f}m"
        else:
            duration_str = f"{d / 3600:.2f}h"

    start_time_str = scan_info.get("start_time", "")
    if start_time_str:
        try:
            dt = datetime.fromisoformat(start_time_str)
            start_time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            pass

    domain = _escape_html(target.get("domain", "unknown"))

    # Build sections
    subdomain_section = _build_subdomain_section(sub_info)
    port_section = _build_port_section(port_info)
    http_section = _build_http_section(http_info)
    shodan_section = _build_shodan_section(enrichment_info)
    cve_section = _build_cve_section(enrichment_info)
    crawl_section = _build_crawl_section(crawl_info)
    dirbuster_section = _build_dirbuster_section(dirbuster_info)
    screenshot_section = _build_screenshot_section(screenshot_info)
    vuln_section = _build_vuln_section(vuln_info)
    ssl_section = _build_ssl_section(ssl_info)
    takeover_section = _build_takeover_section(takeover_info)
    waf_section = _build_waf_section(waf_info)
    exploit_section = _build_exploit_section(exploit_info)
    payload_section = _build_payload_section(payload_info)
    loot_section = _build_loot_section(loot_info)
    msf_section = _build_msf_section(msf_info)
    osint_section = _build_osint_section(osint_info)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconProbe — {domain}</title>
<script src="{CHARTJS_CDN}"></script>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
    background: #0f1117; color: #e2e8f0; min-height: 100vh;
  }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 24px 20px; }}

  /* Header */
  .header {{
    display: flex; align-items: center; justify-content: space-between;
    padding: 20px 0; border-bottom: 1px solid #1e293b; margin-bottom: 28px; flex-wrap: wrap; gap: 12px;
  }}
  .header-left h1 {{
    font-size: 28px; font-weight: 700; letter-spacing: -0.5px;
    background: linear-gradient(135deg, #06b6d4, #8b5cf6); -webkit-background-clip: text;
    -webkit-text-fill-color: transparent; background-clip: text;
  }}
  .header-left .subtitle {{ font-size: 14px; color: #94a3b8; margin-top: 4px; }}
  .header-right {{ text-align: right; }}
  .header-right .domain {{ font-size: 18px; font-weight: 600; color: #f1f5f9; }}
  .header-right .meta {{ font-size: 13px; color: #64748b; }}

  /* Summary Cards */
  .cards {{
    display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 16px; margin-bottom: 32px;
  }}
  .card {{
    background: #1a1d29; border: 1px solid #2d3148; border-radius: 12px;
    padding: 18px 16px; text-align: center; transition: transform 0.15s, box-shadow 0.15s;
  }}
  .card:hover {{ transform: translateY(-2px); box-shadow: 0 4px 20px rgba(0,0,0,0.3); }}
  .card .value {{ font-size: 32px; font-weight: 700; line-height: 1.2; }}
  .card .label {{ font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
  .card-green .value {{ color: #22c55e; }}
  .card-cyan .value {{ color: #06b6d4; }}
  .card-amber .value {{ color: #f59e0b; }}
  .card-red .value {{ color: #ef4444; }}
  .card-purple .value {{ color: #a855f7; }}
  .card-blue .value {{ color: #3b82f6; }}
  .card-pink .value {{ color: #ec4899; }}
  .card-orange .value {{ color: #f97316; }}

  /* Charts Grid */
  .charts {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
    gap: 20px; margin-bottom: 32px;
  }}
  .chart-box {{
    background: #1a1d29; border: 1px solid #2d3148; border-radius: 12px;
    padding: 20px; position: relative;
  }}
  .chart-box h3 {{ font-size: 14px; color: #94a3b8; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 1px; }}

  /* Collapsible Sections */
  .section {{ margin-bottom: 20px; }}
  .section-toggle {{
    width: 100%; display: flex; align-items: center; justify-content: space-between;
    background: #1a1d29; border: 1px solid #2d3148; border-radius: 12px;
    padding: 14px 20px; cursor: pointer; font-size: 15px; font-weight: 600;
    color: #e2e8f0; transition: background 0.15s;
  }}
  .section-toggle:hover {{ background: #22263a; }}
  .section-toggle .arrow {{ transition: transform 0.2s; font-size: 12px; color: #64748b; }}
  .section-toggle.active .arrow {{ transform: rotate(90deg); }}
  .section-toggle .count {{ font-size: 12px; font-weight: 400; color: #94a3b8; }}
  .section-content {{ display: none; padding: 16px 0; }}
  .section-content.open {{ display: block; }}

  /* Tables */
  .table-wrap {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 10px 12px; background: #1e2235; color: #94a3b8; font-weight: 600; border-bottom: 1px solid #2d3148; white-space: nowrap; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #1e293b; }}
  tr:hover td {{ background: #1a1e30; }}
  td .mono {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: 12px; }}

  /* Badges */
  .badge {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 500; margin: 1px;
  }}
  .badge-tech {{ background: #1e3a5f; color: #93c5fd; }}
  .badge-server {{ background: #3b1f3b; color: #d8b4fe; }}
  .badge-cms {{ background: #1f3b2f; color: #86efac; }}
  .badge-js {{ background: #3b3520; color: #fde68a; }}
  .badge-cdn {{ background: #1f353b; color: #67e8f9; }}
  .badge-sec {{ background: #3b2020; color: #fca5a5; }}
  .badge-critical {{ background: #450a0a; color: #fca5a5; }}
  .badge-high {{ background: #7f1d1d; color: #fca5a5; }}
  .badge-medium {{ background: #713f12; color: #fde68a; }}
  .badge-low {{ background: #422f0a; color: #fef9c3; }}
  .badge-none {{ background: #374151; color: #d1d5db; }}

  .status-dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }}

  /* Info panels */
  .info-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px;
  }}
  .info-card {{
    background: #11131e; border: 1px solid #1e2235; border-radius: 8px; padding: 14px;
  }}
  .info-card h4 {{ font-size: 13px; color: #94a3b8; margin-bottom: 6px; }}
  .info-card .val {{ font-size: 14px; color: #f1f5f9; }}

  .tech-list {{ display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }}

  /* Finding items */
  .finding-item {{ padding: 6px 0; border-bottom: 1px solid #1e293b; font-size: 13px; }}
  .finding-item:last-child {{ border: none; }}
  .finding-type {{ font-weight: 600; color: #f59e0b; }}
  .finding-detail {{ color: #94a3b8; }}

  /* Responsive */
  @media (max-width: 768px) {{
    .charts {{ grid-template-columns: 1fr; }}
    .cards {{ grid-template-columns: repeat(2, 1fr); }}
    .header {{ flex-direction: column; text-align: center; }}
    .header-right {{ text-align: center; }}
  }}

  /* Scrollbar */
  ::-webkit-scrollbar {{ width: 8px; height: 8px; }}
  ::-webkit-scrollbar-track {{ background: #0f1117; }}
  ::-webkit-scrollbar-thumb {{ background: #2d3148; border-radius: 4px; }}
  ::-webkit-scrollbar-thumb:hover {{ background: #3d4168; }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <h1>🔍 ReconProbe</h1>
      <div class="subtitle">Automated Reconnaissance Report</div>
    </div>
    <div class="header-right">
      <div class="domain">{domain}</div>
      <div class="meta">{start_time_str} &middot; Duration: {duration_str}</div>
    </div>
  </div>

  <!-- Summary Cards -->
  <div class="cards">
    <div class="card card-cyan">
      <div class="value">{total_subdomains}</div>
      <div class="label">Subdomains Found</div>
      <div style="font-size:11px;color:#64748b;">{total_resolved} resolved</div>
    </div>
    <div class="card card-green">
      <div class="value">{total_open_ports}</div>
      <div class="label">Open Ports</div>
      <div style="font-size:11px;color:#64748b;">across {port_info.get('total_hosts_scanned', 0)} hosts</div>
    </div>
    <div class="card card-blue">
      <div class="value">{total_alive}</div>
      <div class="label">Alive HTTP Services</div>
      <div style="font-size:11px;color:#64748b;">{http_info.get('total_hosts_probed', 0)} hosts probed</div>
    </div>
    <div class="card card-red">
      <div class="value">{total_cves}</div>
      <div class="label">CVEs Found</div>
      <div style="font-size:11px;color:#64748b;">{high_critical_cves} high/critical</div>
    </div>
    <div class="card card-purple">
      <div class="value">{total_crawled}</div>
      <div class="label">Pages Crawled</div>
      <div style="font-size:11px;color:#64748b;">{total_crawl_findings} findings</div>
    </div>
    <div class="card card-amber">
      <div class="value">{total_dirb_found}</div>
      <div class="label">DirBuster Hits</div>
      <div style="font-size:11px;color:#64748b;">{dirbuster_info.get('total_paths_scanned', 0)} scanned</div>
    </div>
    <div class="card card-pink">
      <div class="value">{screenshot_info.get('total_taken', 0)}</div>
      <div class="label">Screenshots</div>
      <div style="font-size:11px;color:#64748b;">{screenshot_info.get('total_failed', 0)} failed</div>
    </div>
    <div class="card card-red">
      <div class="value">{total_vuln_cves}</div>
      <div class="label">Vuln CVEs</div>
      <div style="font-size:11px;color:#64748b;">{total_vuln_high} high/critical</div>
    </div>
    <div class="card card-orange">
      <div class="value">{total_ssl_endpoints}</div>
      <div class="label">SSL/TLS Audited</div>
      <div style="font-size:11px;color:#64748b;">cert+protocol+headers</div>
    </div>
    <div class="card card-amber">
      <div class="value">{total_takeover_vulns}</div>
      <div class="label">Takeover Vulns</div>
      <div style="font-size:11px;color:#64748b;">dangling DNS + HTTP</div>
    </div>
    <div class="card card-purple">
      <div class="value">{total_waf_protected}</div>
      <div class="label">WAFs Detected</div>
      <div style="font-size:11px;color:#64748b;">passive + active</div>
    </div>
    <div class="card card-cyan">
      <div class="value">{total_exploit_suggestions}</div>
      <div class="label">Exploit Suggests</div>
      <div style="font-size:11px;color:#64748b;">matched services</div>
    </div>
    <div class="card card-green">
      <div class="value">{total_payloads}</div>
      <div class="label">Payloads Generated</div>
      <div style="font-size:11px;color:#64748b;">reverse shells</div>
    </div>
    <div class="card card-red">
      <div class="value">{total_loot_critical}</div>
      <div class="label">Critical Loot</div>
      <div style="font-size:11px;color:#64748b;">{total_loot_items} total items</div>
    </div>
    <div class="card card-blue">
      <div class="value">{total_msf_modules}</div>
      <div class="label">MSF Modules</div>
      <div style="font-size:11px;color:#64748b;">resource script</div>
    </div>
    <div class="card card-purple">
      <div class="value">{total_osint_findings}</div>
      <div class="label">OSINT Findings</div>
      <div style="font-size:11px;color:#64748b;">{total_osint_critical} critical, {total_osint_high} high</div>
    </div>
  </div>

  <!-- Charts -->
  <div class="charts" id="chartsContainer">
    <div class="chart-box">
      <h3>Subdomains by Source</h3>
      <canvas id="chartSubdomain"></canvas>
    </div>
    <div class="chart-box">
      <h3>Open Ports by Service</h3>
      <canvas id="chartPorts"></canvas>
    </div>
    <div class="chart-box">
      <h3>HTTP Status Codes</h3>
      <canvas id="chartStatus"></canvas>
    </div>
    <div class="chart-box">
      <h3>Technology Distribution</h3>
      <canvas id="chartTech"></canvas>
    </div>
    <div class="chart-box">
      <h3>CVEs by Severity</h3>
      <canvas id="chartCVE"></canvas>
    </div>
    <div class="chart-box">
      <h3>Port Distribution</h3>
      <canvas id="chartPortDist"></canvas>
    </div>
    <div class="chart-box">
      <h3>Vuln CVEs by Severity</h3>
      <canvas id="chartVulnCVE"></canvas>
    </div>
    <div class="chart-box">
      <h3>Exploit Suggestions by Reliability</h3>
      <canvas id="chartExploit"></canvas>
    </div>
  </div>

  <!-- Collapsible Sections -->
  {subdomain_section}
  {port_section}
  {http_section}
  {shodan_section}
  {cve_section}
  {crawl_section}
  {dirbuster_section}
  {screenshot_section}
  {vuln_section}
  {ssl_section}
  {takeover_section}
  {waf_section}
  {exploit_section}
  {payload_section}
  {loot_section}
  {msf_section}
  {osint_section}

  <!-- Footer -->
  <div style="text-align:center;padding:32px 0 16px;border-top:1px solid #1e293b;margin-top:32px;">
    <p style="font-size:12px;color:#475569;">
      Generated by <strong>ReconProbe v{_escape_html(str(report.get('version', '')))}</strong> &middot;
      Charts powered by <a href="https://www.chartjs.org" style="color:#06b6d4;" target="_blank">Chart.js</a>
    </p>
  </div>

</div>

<script>
  // Chart data
  const chartData = {json.dumps(chart_data)};

  // Default chart options
  const chartDefaults = {{
    responsive: true,
    maintainAspectRatio: true,
    plugins: {{
      legend: {{ labels: {{ color: '#94a3b8', font: {{ size: 11 }} }} }},
    }},
  }};

  // Color palette
  const colors = [
    '#06b6d4', '#8b5cf6', '#22c55e', '#f59e0b', '#ef4444',
    '#3b82f6', '#ec4899', '#14b8a6', '#f97316', '#a855f7',
    '#84cc16', '#06b6d4', '#64748b', '#f43f5e', '#0ea5e9'
  ];

  // 1. Subdomain by Source
  if (chartData.subdomainSources) {{
    new Chart(document.getElementById('chartSubdomain'), {{
      type: 'doughnut',
      data: {{
        labels: chartData.subdomainSources.labels,
        datasets: [{{
          data: chartData.subdomainSources.values,
          backgroundColor: colors.slice(0, chartData.subdomainSources.labels.length),
          borderWidth: 0,
        }}]
      }},
      options: {{ ...chartDefaults, cutout: '65%' }}
    }});
  }}

  // 2. Open Ports by Service
  if (chartData.portServices) {{
    new Chart(document.getElementById('chartPorts'), {{
      type: 'bar',
      data: {{
        labels: chartData.portServices.labels,
        datasets: [{{
          label: 'Ports',
          data: chartData.portServices.values,
          backgroundColor: colors.slice(0, chartData.portServices.labels.length),
          borderRadius: 4,
        }}]
      }},
      options: {{
        ...chartDefaults,
        indexAxis: 'y',
        scales: {{
          x: {{ beginAtZero: true, ticks: {{ color: '#64748b', stepSize: 1 }}, grid: {{ color: '#1e293b' }} }},
          y: {{ ticks: {{ color: '#94a3b8', font: {{ size: 10 }} }}, grid: {{ display: false }} }}
        }}
      }}
    }});
  }}

  // 3. HTTP Status Codes
  if (chartData.statusCodes) {{
    new Chart(document.getElementById('chartStatus'), {{
      type: 'bar',
      data: {{
        labels: chartData.statusCodes.labels,
        datasets: [{{
          label: 'Responses',
          data: chartData.statusCodes.values,
          backgroundColor: chartData.statusCodes.colors,
          borderRadius: 4,
        }}]
      }},
      options: {{
        ...chartDefaults,
        scales: {{
          y: {{ beginAtZero: true, ticks: {{ color: '#64748b', stepSize: 1 }}, grid: {{ color: '#1e293b' }} }},
          x: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ display: false }} }}
        }}
      }}
    }});
  }}

  // 4. Technology Distribution
  if (chartData.techCategories) {{
    new Chart(document.getElementById('chartTech'), {{
      type: 'polarArea',
      data: {{
        labels: chartData.techCategories.labels,
        datasets: [{{
          data: chartData.techCategories.values,
          backgroundColor: colors.slice(0, chartData.techCategories.labels.length).map(c => c + '80'),
          borderColor: colors.slice(0, chartData.techCategories.labels.length),
          borderWidth: 1,
        }}]
      }},
      options: {{
        ...chartDefaults,
        scales: {{ r: {{ ticks: {{ display: false }}, grid: {{ color: '#1e293b' }} }} }}
      }}
    }});
  }}

  // 5. CVEs by Severity
  if (chartData.cveSeverity) {{
    new Chart(document.getElementById('chartCVE'), {{
      type: 'doughnut',
      data: {{
        labels: chartData.cveSeverity.labels,
        datasets: [{{
          data: chartData.cveSeverity.values,
          backgroundColor: chartData.cveSeverity.colors,
          borderWidth: 0,
        }}]
      }},
      options: {{ ...chartDefaults, cutout: '60%' }}
    }});
  }}

  // 6. Port Distribution (count of hosts per port)
  if (chartData.portDistribution) {{
    new Chart(document.getElementById('chartPortDist'), {{
      type: 'bar',
      data: {{
        labels: chartData.portDistribution.labels,
        datasets: [{{
          label: 'Hosts',
          data: chartData.portDistribution.values,
          backgroundColor: '#8b5cf6',
          borderRadius: 4,
        }}]
      }},
      options: {{
        ...chartDefaults,
        scales: {{
          y: {{ beginAtZero: true, ticks: {{ color: '#64748b', stepSize: 1 }}, grid: {{ color: '#1e293b' }} }},
          x: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ display: false }} }}
        }}
      }}
    }});
  }}

  // 7. Exploit Suggestions by Reliability
  if (chartData.exploitReliability) {{
    new Chart(document.getElementById('chartExploit'), {{
      type: 'doughnut',
      data: {{
        labels: chartData.exploitReliability.labels,
        datasets: [{{
          data: chartData.exploitReliability.values,
          backgroundColor: chartData.exploitReliability.colors,
          borderWidth: 0,
        }}]
      }},
      options: {{ ...chartDefaults, cutout: '60%' }}
    }});
  }}

  // Toggle sections
  document.querySelectorAll('.section-toggle').forEach(toggle => {{
    toggle.addEventListener('click', () => {{
      const content = toggle.nextElementSibling;
      const isOpen = content.classList.contains('open');
      content.classList.toggle('open');
      toggle.classList.toggle('active');
    }});
  }});

  // Auto-open first section if it has data
  document.querySelectorAll('.section-toggle').forEach(toggle => {{
    const content = toggle.nextElementSibling;
    if (content && content.querySelector('table') && content.querySelector('tbody tr')) {{
      content.classList.add('open');
      toggle.classList.add('active');
    }}
  }});
</script>
</body>
</html>"""
    return html


def _build_chart_data(report: dict) -> dict:
    """Build chart data from scan report."""
    data: dict = {}

    # 1. Subdomains by source
    sub_info = report.get("subdomain_enumeration", {})
    source_counts: dict[str, int] = {}
    for r in sub_info.get("results", []):
        src = r.get("source", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1
    if source_counts:
        data["subdomainSources"] = {
            "labels": list(source_counts.keys()),
            "values": list(source_counts.values()),
        }

    # 2. Open ports by service (top 10)
    port_info = report.get("port_scanning", {})
    service_counts: dict[str, int] = {}
    port_dist: dict[int, int] = {}
    for host in port_info.get("hosts", []):
        for p in host.get("ports", []):
            if p.get("state") == "open":
                svc = p.get("service", str(p["port"]))
                service_counts[svc] = service_counts.get(svc, 0) + 1
                port_num = p["port"]
                port_dist[port_num] = port_dist.get(port_num, 0) + 1
    if service_counts:
        sorted_services = sorted(service_counts.items(), key=lambda x: -x[1])[:10]
        data["portServices"] = {
            "labels": [s[0] for s in sorted_services],
            "values": [s[1] for s in sorted_services],
        }
    if port_dist:
        sorted_ports = sorted(port_dist.items())
        data["portDistribution"] = {
            "labels": [f":{p[0]}" for p in sorted_ports],
            "values": [p[1] for p in sorted_ports],
        }

    # 3. HTTP Status codes
    http_info = report.get("http_probing", {})
    status_counts: dict[str, int] = {}
    for hostname, host_data in http_info.get("hosts", {}).items():
        for result in host_data.get("results", []):
            code = result.get("status_code", 0)
            label = f"{code}"
            status_counts[label] = status_counts.get(label, 0) + 1
    if status_counts:
        sorted_status = sorted(status_counts.items(), key=lambda x: -x[1])
        data["statusCodes"] = {
            "labels": [s[0] for s in sorted_status],
            "values": [s[1] for s in sorted_status],
            "colors": [_status_color(int(s[0])) for s in sorted_status],
        }

    # 4. Technology categories
    cat_counts: dict[str, int] = {}
    for hostname, host_data in http_info.get("hosts", {}).items():
        for result in host_data.get("results", []):
            for tech in result.get("technologies", []):
                cat = tech.get("category", "Other")
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
    if cat_counts:
        sorted_cats = sorted(cat_counts.items(), key=lambda x: -x[1])
        data["techCategories"] = {
            "labels": [c[0] for c in sorted_cats],
            "values": [c[1] for c in sorted_cats],
        }

    # 5. Vuln Scan CVE severity
    vuln_info = report.get("vulnerability_scan", {})
    vuln_cves = vuln_info.get("cve_matches", [])
    if vuln_cves:
        vsev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
        for cve in vuln_cves:
            sev = cve.get("cvss_severity", "NONE").upper()
            if sev not in vsev_counts:
                sev = "NONE"
            vsev_counts[sev] += 1
        vfiltered = {k: v for k, v in vsev_counts.items() if v > 0}
        if vfiltered:
            data["vulnCveSeverity"] = {
                "labels": list(vfiltered.keys()),
                "values": list(vfiltered.values()),
                "colors": [_severity_color(k) for k in vfiltered.keys()],
            }

    # 7. Exploit suggestions by reliability
    exploit_info = report.get("exploit_suggestions", {})
    suggestions = exploit_info.get("suggestions", [])
    if suggestions:
        rel_counts = {"high": 0, "medium": 0, "low": 0}
        for s in suggestions:
            rel = s.get("reliability", "low").lower()
            if rel in rel_counts:
                rel_counts[rel] += 1
        if any(v > 0 for v in rel_counts.values()):
            rel_colors = {"high": "#ef4444", "medium": "#f59e0b", "low": "#94a3b8"}
            filtered = {k: v for k, v in rel_counts.items() if v > 0}
            data["exploitReliability"] = {
                "labels": list(filtered.keys()),
                "values": list(filtered.values()),
                "colors": [rel_colors[k] for k in filtered.keys()],
            }

    # 6. CVEs by severity (existing from enrichment)
    cve_results = report.get("enrichment", {}).get("cve_lookup", {}).get("results", [])
    sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
    for cve in cve_results:
        sev = cve.get("cvss_severity", "NONE").upper()
        if sev not in sev_counts:
            sev = "NONE"
        sev_counts[sev] += 1
    filtered = {k: v for k, v in sev_counts.items() if v > 0}
    if filtered:
        data["cveSeverity"] = {
            "labels": list(filtered.keys()),
            "values": list(filtered.values()),
            "colors": [_severity_color(k) for k in filtered.keys()],
        }

    return data


def _build_subdomain_section(sub_info: dict) -> str:
    results = sub_info.get("results", [])
    if not results:
        return ""

    rows = ""
    for r in results:
        resolved = r.get("resolved", False)
        dot_color = "#22c55e" if resolved else "#ef4444"
        ip = r.get("ip_address") or "-"
        hostname = _escape_html(r.get("hostname", ""))
        source = _escape_html(r.get("source", ""))
        rows += f"<tr><td><span class=\"status-dot\" style=\"background:{dot_color}\"></span>{hostname}</td><td class=\"mono\">{_escape_html(ip)}</td><td>{source}</td></tr>"

    return f"""
<div class="section">
  <div class="section-toggle">
    <span>🌐 Subdomain Enumeration <span class="count">({len(results)} results)</span></span>
    <span class="arrow">▶</span>
  </div>
  <div class="section-content">
    <div class="table-wrap">
      <table>
        <thead><tr><th>Hostname</th><th>IP Address</th><th>Source</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  </div>
</div>"""


def _build_port_section(port_info: dict) -> str:
    hosts = port_info.get("hosts", [])
    if not hosts:
        return ""

    host_sections = ""
    for host in hosts:
        hostname = _escape_html(host.get("hostname", ""))
        ip = _escape_html(host.get("ip_address", ""))
        ports = [p for p in host.get("ports", []) if p.get("state") == "open"]
        if not ports:
            continue

        rows = ""
        for p in ports:
            banner = p.get("banner", "") or ""
            banner_short = _escape_html(banner[:60] + "..." if len(banner) > 60 else banner)
            port_num = p.get("port", "")
            service = _escape_html(p.get("service", ""))
            rows += f"<tr><td class=\"mono\">{port_num}</td><td>{service}</td><td class=\"mono\">{banner_short}</td></tr>"

        host_sections += f"""
<h4 style="color:#06b6d4;margin:12px 0 8px;">{hostname} ({ip}) — {len(ports)} open</h4>
<div class="table-wrap">
  <table>
    <thead><tr><th>Port</th><th>Service</th><th>Banner</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""

    return f"""
<div class="section">
  <div class="section-toggle">
    <span>🔌 Port Scanning <span class="count">({len(hosts)} hosts, {sum(h.get('open_ports',0) for h in hosts)} open)</span></span>
    <span class="arrow">▶</span>
  </div>
  <div class="section-content">
    {host_sections}
  </div>
</div>"""


def _build_http_section(http_info: dict) -> str:
    hosts = http_info.get("hosts", {})
    if not hosts:
        return ""

    host_sections = ""
    for hostname, host_data in hosts.items():
        results = host_data.get("results", [])
        if not results:
            continue

        host_html = ""
        for result in results:
            status = result.get("status_code", 0)
            url = _escape_html(result.get("url", ""))
            title = _escape_html(result.get("title", "") or "")
            server = _escape_html(result.get("server", "") or "")
            techs = result.get("technologies", [])

            tech_badges = ""
            cat_map = {
                "Web Server": "badge-server", "Security": "badge-sec",
                "CDN": "badge-cdn", "CMS": "badge-cms",
                "JavaScript Framework": "badge-js",
            }
            for t in techs:
                cat = t.get("category", "")
                cls = cat_map.get(cat, "badge-tech")
                tech_badges += f'<span class="badge {cls}">{_escape_html(t["name"])}</span>'

            status_bg = _status_color(status)
            host_html += f"""
<div class="info-card">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
    <span style="background:{status_bg};padding:2px 8px;border-radius:4px;font-weight:700;font-size:13px;">{status}</span>
    <span class="mono" style="font-size:13px;color:#f1f5f9;">{url}</span>
  </div>
  {f'<div style="font-size:14px;color:#e2e8f0;margin-bottom:4px;">{title}</div>' if title else ''}
  {f'<div style="font-size:12px;color:#64748b;">Server: {server}</div>' if server else ''}
  <div class="tech-list">{tech_badges}</div>
</div>"""

        host_sections += f"""
<h4 style="color:#06b6d4;margin:12px 0 8px;">{_escape_html(hostname)}</h4>
<div class="info-grid">{host_html}</div>"""

    return f"""
<div class="section">
  <div class="section-toggle">
    <span>🌍 HTTP Probing &amp; Technology <span class="count">({http_info.get('total_alive_services', 0)} alive)</span></span>
    <span class="arrow">▶</span>
  </div>
  <div class="section-content">
    {host_sections}
  </div>
</div>"""


def _build_shodan_section(enrichment_info: dict) -> str:
    shodan_data = enrichment_info.get("shodan", {})
    results = shodan_data.get("results", {})
    if not results:
        return ""

    ip_sections = ""
    for ip, sr in results.items():
        if sr.get("error"):
            ip_sections += f'<div class="info-card"><h4>{_escape_html(ip)}</h4><div class="val" style="color:#ef4444;">Error: {_escape_html(sr["error"])}</div></div>'
            continue

        org = sr.get("org") or sr.get("isp") or ""
        hostnames = ", ".join(sr.get("hostnames", [])) if sr.get("hostnames") else ""
        country = sr.get("country", "")
        open_ports = sr.get("open_ports", [])
        vulns = sr.get("vulns", [])
        services = sr.get("services", [])[:10]

        vuln_badges = ""
        for v in vulns[:20]:
            vuln_badges += f'<span class="badge badge-high">{_escape_html(v)}</span>'
        if len(vulns) > 20:
            vuln_badges += f'<span class="badge badge-none">+{len(vulns) - 20} more</span>'

        svc_rows = ""
        for svc in services:
            product = _escape_html(svc.get("product", "") or "-")
            version = _escape_html(svc.get("version", "") or "-")
            transport = svc.get("transport", "tcp")
            svc_rows += f"<tr><td>{svc['port']}/{transport}</td><td>{product}</td><td>{version}</td></tr>"

        ip_sections += f"""
<div class="info-card">
  <h4>{_escape_html(ip)} {f'— {_escape_html(org)}' if org else ''}</h4>
  {f'<div style="font-size:12px;color:#64748b;margin-bottom:4px;">Hostnames: {_escape_html(hostnames)}</div>' if hostnames else ''}
  {f'<div style="font-size:12px;color:#64748b;margin-bottom:4px;">Country: {_escape_html(country)}</div>' if country else ''}
  {f'<div style="font-size:12px;color:#64748b;margin-bottom:4px;">Open Ports: {", ".join(map(str, open_ports))}</div>' if open_ports else ''}
  {f'<div style="margin-top:6px;">Vulns: {vuln_badges}</div>' if vulns else ''}
  {f'<table style="margin-top:8px;font-size:12px;"><thead><tr><th>Port</th><th>Product</th><th>Version</th></tr></thead><tbody>{svc_rows}</tbody></table>' if services else ''}
</div>"""

    return f"""
<div class="section">
  <div class="section-toggle">
    <span>🛡️ Shodan Enrichment <span class="count">({len(results)} IPs)</span></span>
    <span class="arrow">▶</span>
  </div>
  <div class="section-content">
    <div class="info-grid">{ip_sections}</div>
  </div>
</div>"""


def _build_cve_section(enrichment_info: dict) -> str:
    cve_data = enrichment_info.get("cve_lookup", {})
    results = cve_data.get("results", [])
    if not results:
        return ""

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
    sorted_cves = sorted(results, key=lambda c: sev_order.get(c.get("cvss_severity", "NONE").upper(), 99))

    rows = ""
    for cve in sorted_cves:
        cve_id = _escape_html(cve.get("cve_id", ""))
        sev = cve.get("cvss_severity", "").upper()
        score = cve.get("cvss_score")
        score_str = f"{score:.1f}" if score is not None else "-"
        desc = _escape_html((cve.get("description", "") or "")[:120])
        affected = _escape_html(cve.get("affected_product", "") or "")
        badge_cls = _severity_badge_color(sev)
        rows += f"<tr><td class=\"mono\">{cve_id}</td><td><span class=\"badge {badge_cls}\">{sev}</span></td><td>{score_str}</td><td>{desc}</td><td style=\"font-size:11px;color:#64748b;\">{affected}</td></tr>"

    return f"""
<div class="section">
  <div class="section-toggle">
    <span>⚠️ CVE Lookup (NVD) <span class="count">({len(results)} CVEs)</span></span>
    <span class="arrow">▶</span>
  </div>
  <div class="section-content">
    <div class="table-wrap">
      <table>
        <thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Description</th><th>Affected Product</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  </div>
</div>"""


def _build_crawl_section(crawl_info: dict) -> str:
    hosts = crawl_info.get("hosts", {})
    if not hosts:
        return ""

    host_sections = ""
    for hostname, host_data in hosts.items():
        total_pages = host_data.get("total_pages", 0)
        total_links = host_data.get("total_links", 0)
        total_scripts = host_data.get("total_scripts", 0)
        total_forms = host_data.get("total_forms", 0)
        base_url = _escape_html(host_data.get("base_url", ""))
        findings = host_data.get("interesting_findings", [])
        urls = host_data.get("unique_urls", [])[:30]

        findings_html = ""
        for f in findings[:20]:
            ft = _escape_html(f.get("type", ""))
            fd = _escape_html(str(f.get("detail", "")))
            findings_html += f'<div class="finding-item"><span class="finding-type">{ft}:</span> <span class="finding-detail">{fd}</span></div>'

        urls_html = ""
        for u in urls:
            urls_html += f'<div style="font-size:12px;color:#94a3b8;padding:2px 0;">{_escape_html(u)}</div>'

        host_sections += f"""
<div class="info-card">
  <h4>{_escape_html(hostname)} — {base_url}</h4>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:8px 0;">
    <div><span style="font-size:18px;font-weight:700;color:#06b6d4;">{total_pages}</span><br><span style="font-size:11px;color:#64748b;">Pages</span></div>
    <div><span style="font-size:18px;font-weight:700;color:#3b82f6;">{total_links}</span><br><span style="font-size:11px;color:#64748b;">Links</span></div>
    <div><span style="font-size:18px;font-weight:700;color:#a855f7;">{total_scripts}</span><br><span style="font-size:11px;color:#64748b;">Scripts</span></div>
    <div><span style="font-size:18px;font-weight:700;color:#22c55e;">{total_forms}</span><br><span style="font-size:11px;color:#64748b;">Forms</span></div>
  </div>
  {f'<div style="margin-top:4px;"><strong style="font-size:12px;color:#f59e0b;">Findings ({len(findings)}):</strong>{findings_html}</div>' if findings else ''}
  {f'<details style="margin-top:8px;"><summary style="font-size:12px;color:#64748b;cursor:pointer;">Discovered URLs ({len(urls)})</summary><div style="margin-top:4px;max-height:300px;overflow-y:auto;">{urls_html}</div></details>' if urls else ''}
</div>"""

    return f"""
<div class="section">
  <div class="section-toggle">
    <span>🕷️ Web Crawling <span class="count">({crawl_info.get('total_pages_crawled', 0)} pages, {crawl_info.get('total_findings', 0)} findings)</span></span>
    <span class="arrow">▶</span>
  </div>
  <div class="section-content">
    <div class="info-grid">{host_sections}</div>
  </div>
</div>"""


def _build_dirbuster_section(dirbuster_info: dict) -> str:
    hosts = dirbuster_info.get("hosts", {})
    if not hosts:
        return ""

    host_sections = ""
    for hostname, host_data in hosts.items():
        results = host_data.get("results", [])
        if not results:
            continue

        rows = ""
        for r in results[:70]:
            url = _escape_html(r.get("url", ""))
            status = r.get("status_code", 0)
            length = r.get("content_length", 0)
            ct = _escape_html((r.get("content_type", "") or "")[:30])
            title = _escape_html(r.get("title", "") or r.get("redirect_url", "") or "-")
            if len(title) > 60:
                title = title[:60] + "..."
            status_bg = _status_color(status)
            rows += f"<tr><td class=\"mono\" style=\"font-size:11px;\">{url}</td><td><span style=\"background:{status_bg};padding:1px 6px;border-radius:3px;font-weight:600;font-size:11px;\">{status}</span></td><td>{length}</td><td style=\"font-size:11px;\">{ct}</td><td style=\"font-size:11px;color:#94a3b8;\">{title}</td></tr>"

        if len(results) > 70:
            rows += f'<tr><td colspan="5" style="text-align:center;color:#64748b;font-size:12px;">... and {len(results) - 70} more results</td></tr>'

        findings_types = host_data.get("findings_by_type", {})
        breakdown = " | ".join(f"{k}: {v}" for k, v in findings_types.items() if v > 0) if any(findings_types.values()) else ""

        host_sections += f"""
<h4 style="color:#06b6d4;margin:12px 0 8px;">{_escape_html(hostname)} — {_escape_html(host_data.get('base_url', ''))}</h4>
{f'<div style="font-size:12px;color:#64748b;margin-bottom:8px;">{breakdown}</div>' if breakdown else ''}
<div class="table-wrap">
  <table>
    <thead><tr><th>URL</th><th>Status</th><th>Length</th><th>Type</th><th>Title/Redirect</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""

    return f"""
<div class="section">
  <div class="section-toggle">
    <span>📁 Directory Brute-Force <span class="count">({dirbuster_info.get('total_paths_found', 0)} found of {dirbuster_info.get('total_paths_scanned', 0)} scanned)</span></span>
    <span class="arrow">▶</span>
  </div>
  <div class="section-content">
    {host_sections}
  </div>
</div>"""


def _build_screenshot_section(screenshot_info: dict) -> str:
    hosts = screenshot_info.get("hosts", {})
    if not hosts:
        return ""

    host_sections = ""
    for hostname, host_data in hosts.items():
        screenshots = host_data.get("screenshots", [])
        if not screenshots:
            continue

        imgs = ""
        for s in screenshots:
            if s.get("success") and s.get("file_path"):
                # Try to use relative path for HTML display
                img_src = _escape_html(s.get("file_path", ""))
                url = _escape_html(s.get("url", ""))
                # Extract filename and use relative path from HTML report location
                filename = PurePosixPath(img_src).name
                imgs += f'<div style="margin-bottom:12px;"><a href="screenshots/{filename}" target="_blank"><img src="screenshots/{filename}" style="width:100%;max-height:400px;object-fit:cover;border-radius:8px;border:1px solid #2d3148;background:#1a1d29;" loading="lazy" alt="{url}"></a><div style="font-size:11px;color:#64748b;margin-top:4px;">{url}</div></div>'

        host_sections += f"""
<h4 style="color:#06b6d4;margin:12px 0 8px;">{_escape_html(hostname)}</h4>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px;">{imgs}</div>"""

    return f"""
<div class="section">
  <div class="section-toggle">
    <span>📸 Screenshots <span class="count">({screenshot_info.get('total_taken', 0)} taken, {screenshot_info.get('total_failed', 0)} failed)</span></span>
    <span class="arrow">▶</span>
  </div>
  <div class="section-content">
    {host_sections}
  </div>
</div>"""


def _build_vuln_section(vuln_info: dict) -> str:
    """Build Vulnerability Scan collapsible section."""
    cves = vuln_info.get("cve_matches", [])
    creds = vuln_info.get("default_credentials", [])
    if not cves and not creds:
        return ""

    cve_rows = ""
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
    sorted_cves = sorted(cves, key=lambda c: sev_order.get(c.get("cvss_severity", "NONE").upper(), 99))
    for cve in sorted_cves:
        cve_id = _escape_html(cve.get("cve_id", ""))
        sev = cve.get("cvss_severity", "").upper()
        score = cve.get("cvss_score")
        score_str = f"{score:.1f}" if score is not None else "-"
        desc = _escape_html((cve.get("description", "") or "")[:100])
        affected = _escape_html(cve.get("affected_service", "") or "")
        badge_cls = _severity_badge_color(sev)
        cve_rows += f"<tr><td class=\"mono\">{cve_id}</td><td><span class=\"badge {badge_cls}\">{sev}</span></td><td>{score_str}</td><td>{desc}</td><td style=\"font-size:11px;color:#64748b;\">{affected}</td></tr>"

    cred_rows = ""
    for cred in creds:
        hostname = _escape_html(cred.get("hostname", ""))
        svc = _escape_html(cred.get("service", ""))
        port = cred.get("port", 0)
        user = _escape_html(cred.get("username", ""))
        pw = _escape_html(cred.get("password", ""))
        cred_rows += f"<tr><td>{svc}</td><td>{hostname}</td><td>{port}</td><td class=\"mono\">{user}</td><td class=\"mono\">{pw}</td></tr>"

    content = ""
    if cve_rows:
        content += f"""
<h4 style="color:#ef4444;margin:12px 0 8px;">CVE Matches ({len(cves)})</h4>
<div class="table-wrap">
  <table>
    <thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Description</th><th>Service</th></tr></thead>
    <tbody>{cve_rows}</tbody>
  </table>
</div>"""

    if cred_rows:
        content += f"""
<h4 style="color:#f59e0b;margin:12px 0 8px;">Default Credentials Found ({len(creds)})</h4>
<div class="table-wrap">
  <table>
    <thead><tr><th>Service</th><th>Hostname</th><th>Port</th><th>Username</th><th>Password</th></tr></thead>
    <tbody>{cred_rows}</tbody>
  </table>
</div>"""

    total = len(cves) + len(creds)
    return f"""
<div class="section">
  <div class="section-toggle">
    <span>🔬 Vulnerability Scan <span class="count">({len(cves)} CVEs, {len(creds)} creds)</span></span>
    <span class="arrow">▶</span>
  </div>
  <div class="section-content">
    {content}
  </div>
</div>"""


def _build_ssl_section(ssl_info: dict) -> str:
    """Build SSL/TLS Audit collapsible section."""
    results = ssl_info.get("results", {})
    if not results:
        return ""

    endpoint_sections = ""
    for endpoint_key, endpoint_data in results.items():
        grade = endpoint_data.get("grade", "?")
        issues = endpoint_data.get("total_issues", 0)
        cert = endpoint_data.get("certificate", {})
        protos = endpoint_data.get("protocols", [])
        weak_ciphers = endpoint_data.get("weak_ciphers", [])
        headers = endpoint_data.get("security_headers", [])

        grade_color = {"A": "#22c55e", "B": "#3b82f6", "C": "#f59e0b", "D": "#f97316", "F": "#ef4444"}
        gc = grade_color.get(grade, "#94a3b8")

        content = f'<div style="font-size:13px;margin-bottom:8px;">Grade: <span style="font-size:24px;font-weight:700;color:{gc};">{grade}</span> | Issues: {issues}</div>'

        if cert:
            is_expired = cert.get("is_expired", False)
            will_expire = cert.get("will_expire_soon", False)
            days_rem = cert.get("days_remaining", 0)
            is_self = cert.get("is_self_signed", False)
            status_icon = "❌" if is_expired else ("⚠️" if will_expire else "✅")
            content += f"""
<div class="info-card" style="margin-bottom:8px;">
  <h4>Certificate</h4>
  <div style="font-size:12px;color:#94a3b8;">
    <div>Subject: {_escape_html(cert.get('subject', ''))}</div>
    <div>Issuer: {_escape_html(cert.get('issuer', ''))}</div>
    <div>Valid To: {_escape_html(cert.get('valid_to', ''))}</div>
    <div>Status: {status_icon} {is_expired and 'EXPIRED' or (will_expire and f'Expiring soon ({days_rem}d)' or f'Valid ({days_rem}d left)')}</div>
    {f'<div style="color:#ef4444;">Self-Signed: Yes</div>' if is_self else ''}
    {f'<div style="color:#f59e0b;">Wildcard: Yes</div>' if cert.get("is_wildcard", False) else ''}
  </div>
</div>"""

        if protos:
            proto_rows = ""
            for p in protos:
                icon = "✅" if p.get("supported") else "❌"
                proto_rows += f"<tr><td>{p.get('protocol', '')}</td><td>{icon}</td></tr>"
            content += f"""
<div class="table-wrap" style="margin-bottom:8px;">
  <table>
    <thead><tr><th>TLS Protocol</th><th>Supported</th></tr></thead>
    <tbody>{proto_rows}</tbody>
  </table>
</div>"""

        if weak_ciphers:
            cipher_rows = ""
            for c in weak_ciphers:
                cipher_rows += f"<tr><td class=\"mono\">{_escape_html(c.get('cipher', ''))}</td><td style=\"font-size:11px;color:#94a3b8;\">{_escape_html(c.get('reason', ''))}</td></tr>"
            content += f"""
<h4 style="color:#ef4444;font-size:13px;margin:8px 0;">Weak Ciphers ({len(weak_ciphers)})</h4>
<div class="table-wrap">
  <table>
    <thead><tr><th>Cipher</th><th>Reason</th></tr></thead>
    <tbody>{cipher_rows}</tbody>
  </table>
</div>"""

        if headers:
            header_rows = ""
            for h in headers:
                icon = "✅" if h.get("present") else "❌"
                val = _escape_html(h.get("value", "")[:60])
                header_rows += f"<tr><td class=\"mono\">{_escape_html(h.get('header', ''))}</td><td>{icon}</td><td style=\"font-size:11px;color:#94a3b8;\">{val or '-'}</td></tr>"
            content += f"""
<h4 style="color:#3b82f6;font-size:13px;margin:8px 0;">Security Headers</h4>
<div class="table-wrap">
  <table>
    <thead><tr><th>Header</th><th>Present</th><th>Value</th></tr></thead>
    <tbody>{header_rows}</tbody>
  </table>
</div>"""

        endpoint_sections += f"""
<div class="info-card">
  <h4 style="font-size:14px;">{_escape_html(endpoint_key)}</h4>
  {content}
</div>"""

    return f"""
<div class="section">
  <div class="section-toggle">
    <span>🔒 SSL/TLS Audit <span class="count">({len(results)} endpoints)</span></span>
    <span class="arrow">▶</span>
  </div>
  <div class="section-content">
    <div class="info-grid">{endpoint_sections}</div>
  </div>
</div>"""


def _build_takeover_section(takeover_info: dict) -> str:
    """Build Subdomain Takeover Detection collapsible section."""
    results = takeover_info.get("results", [])
    if not results:
        return ""

    rows = ""
    for r in results:
        hostname = _escape_html(r.get("hostname", ""))
        service = _escape_html(r.get("service", ""))
        confidence = r.get("confidence", "")
        dns_status = r.get("dns_status", "")
        confidence_color = "red" if confidence == "high" else ("yellow" if confidence == "medium" else "gray")
        rows += f"<tr><td class=\"mono\">{hostname}</td><td>{service}</td><td style=\"color:{confidence_color};\">{confidence}</td><td>{dns_status}</td></tr>"

    return f"""
<div class="section">
  <div class="section-toggle">
    <span>🏳️ Subdomain Takeover Detection <span class="count">({takeover_info.get('total_vulnerable', 0)} vulns, {takeover_info.get('total_checked', 0)} checked)</span></span>
    <span class="arrow">▶</span>
  </div>
  <div class="section-content">
    <div class="table-wrap">
      <table>
        <thead><tr><th>Hostname</th><th>Service</th><th>Confidence</th><th>DNS Status</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  </div>
</div>"""


def _build_exploit_section(exploit_info: dict) -> str:
    """Build Exploit Suggestions collapsible section."""
    suggestions = exploit_info.get("suggestions", [])
    if not suggestions:
        return ""

    rows = ""
    for s in suggestions[:30]:
        edb = _escape_html(s.get("edb_id", ""))
        cve = _escape_html(s.get("cve_id", "") or "-")
        svc = _escape_html(s.get("service", ""))
        rel = s.get("reliability", "")
        etype = _escape_html(s.get("exploit_type", ""))
        port = s.get("port", "") or "-"
        title = _escape_html(s.get("title", "")[:70])
        rel_color = {"high": "#ef4444", "medium": "#f59e0b", "low": "#94a3b8"}
        rc = rel_color.get(rel, "#94a3b8")
        rows += f"<tr><td class=\"mono\" style=\"font-size:11px;\">{edb}</td><td class=\"mono\" style=\"font-size:11px;\">{cve}</td><td>{svc}</td><td style=\"color:{rc};\">{rel}</td><td>{etype}</td><td>{port}</td><td style=\"font-size:11px;color:#94a3b8;\">{title}</td></tr>"

    if len(suggestions) > 30:
        rows += f'<tr><td colspan="7" style="text-align:center;color:#64748b;font-size:12px;">... and {len(suggestions) - 30} more</td></tr>'

    return f"""
<div class="section">
  <div class="section-toggle">
    <span>🎯 Exploit Suggestions <span class="count">({exploit_info.get('total_suggestions', 0)} suggestions)</span></span>
    <span class="arrow">▶</span>
  </div>
  <div class="section-content">
    <div class="table-wrap">
      <table>
        <thead><tr><th>EDB ID</th><th>CVE ID</th><th>Service</th><th>Reliability</th><th>Type</th><th>Port</th><th>Title</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  </div>
</div>"""


def _build_payload_section(payload_info: dict) -> str:
    """Build Payload Generation collapsible section."""
    payloads = payload_info.get("payloads", [])
    if not payloads:
        return ""

    lh = _escape_html(payload_info.get("lhost", "127.0.0.1"))
    lp = payload_info.get("lport", 4444)

    cards = ""
    for p in payloads:
        cmd = _escape_html(p.get("command", ""))
        listener = _escape_html(p.get("listener_command", ""))
        desc = _escape_html(p.get("description", p.get("type", "")))
        encoded = p.get("encoded", False)
        enc_cmd = _escape_html(p.get("encoded_command", "")) if encoded else ""

        extra = ""
        if encoded and enc_cmd:
            extra = f'<div style="margin-top:6px;"><span class="badge badge-medium">Encoded</span><pre style="font-size:11px;background:#0f1117;padding:8px;border-radius:4px;margin-top:4px;overflow-x:auto;">{enc_cmd[:120]}</pre></div>'

        cards += f"""
<div class="info-card">
  <h4>{desc}</h4>
  <pre style="font-size:12px;background:#0f1117;padding:8px;border-radius:4px;margin:6px 0;overflow-x:auto;">{cmd}</pre>
  <div style="font-size:11px;color:#64748b;">Listener: <code style="color:#22c55e;">{listener}</code></div>
  {extra}
</div>"""

    return f"""
<div class="section">
  <div class="section-toggle">
    <span>💻 Payload Generation <span class="count">({len(payloads)} payloads, {lh}:{lp})</span></span>
    <span class="arrow">▶</span>
  </div>
  <div class="section-content">
    <div class="info-grid">{cards}</div>
  </div>
</div>"""


def _build_loot_section(loot_info: dict) -> str:
    """Build Loot Collection collapsible section."""
    items = loot_info.get("items", [])
    if not items:
        return ""

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_items = sorted(items, key=lambda i: sev_order.get(i.get("severity", "info"), 99))

    rows = ""
    for item in sorted_items[:40]:
        itype = _escape_html(item.get("type", ""))
        src = _escape_html(item.get("source", ""))
        tgt = _escape_html(item.get("target", ""))
        sev = item.get("severity", "info")
        desc = _escape_html(item.get("description", "") or "")[:60]
        data_str = str(item.get("data", ""))[:40]
        if len(data_str) == 40:
            data_str += "..."
        data_str = _escape_html(data_str)

        sev_colors = {"critical": "#ef4444", "high": "#f59e0b", "medium": "#d97706", "low": "#94a3b8", "info": "#6b7280"}
        sc = sev_colors.get(sev, "#6b7280")
        rows += f"<tr><td>{itype}</td><td style=\"font-size:11px;\">{src}</td><td>{tgt}</td><td style=\"color:{sc};\">{sev}</td><td style=\"font-size:11px;color:#94a3b8;\">{desc}</td><td class=\"mono\" style=\"font-size:11px;\">{data_str}</td></tr>"

    if len(sorted_items) > 40:
        rows += f'<tr><td colspan="6" style="text-align:center;color:#64748b;font-size:12px;">... and {len(sorted_items) - 40} more items</td></tr>'

    return f"""
<div class="section">
  <div class="section-toggle">
    <span>💰 Loot Collection <span class="count">({loot_info.get('total_count', 0)} items, {loot_info.get('critical_count', 0)} critical)</span></span>
    <span class="arrow">▶</span>
  </div>
  <div class="section-content">
    <div class="table-wrap">
      <table>
        <thead><tr><th>Type</th><th>Source</th><th>Target</th><th>Severity</th><th>Description</th><th>Data</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  </div>
</div>"""


def _build_msf_section(msf_info: dict) -> str:
    """Build Metasploit Script collapsible section."""
    content = msf_info.get("content", "")
    if not content:
        return ""

    # Show first 40 lines of the MSF script
    content_lines = content.split("\n")
    preview = "\n".join(content_lines[:40])
    preview_escaped = _escape_html(preview)
    more = f"\n# ... ({len(content_lines) - 40} more lines)" if len(content_lines) > 40 else ""

    return f"""
<div class="section">
  <div class="section-toggle">
    <span>⚡ Metasploit Resource Script <span class="count">({msf_info.get('module_count', 0)} modules, {msf_info.get('exploit_count', 0)} exploits)</span></span>
    <span class="arrow">▶</span>
  </div>
  <div class="section-content">
    <div style="margin-bottom:8px;">
      <span class="badge badge-blue">{msf_info.get('auxiliary_count', 0)} auxiliary</span>
      <span class="badge badge-red">{msf_info.get('exploit_count', 0)} exploits</span>
      <span class="badge badge-medium">{msf_info.get('module_count', 0)} total modules</span>
    </div>
    <pre style="background:#0f1117;padding:12px;border-radius:8px;overflow-x:auto;font-size:12px;line-height:1.5;color:#e2e8f0;">{preview_escaped}{more}</pre>
  </div>
</div>"""


def _build_osint_section(osint_info: dict) -> str:
    """Build Advanced OSINT collapsible section."""
    findings = osint_info.get("findings", [])
    if not findings:
        return ""

    source_counts = osint_info.get("source_counts", {})
    severity_counts = osint_info.get("severity_counts", {})

    # Group by source
    sources_order = ["github", "google_dork", "whois", "email", "social", "breach", "tech_stack"]
    source_labels = {
        "github": "GitHub Dorking",
        "google_dork": "Google Dorking",
        "whois": "WHOIS Lookup",
        "email": "Email Harvesting",
        "social": "Social Footprinting",
        "breach": "Breach Check",
        "tech_stack": "Tech Stack OSINT",
    }
    source_colors = {
        "github": "#6e5494",
        "google_dork": "#4285f4",
        "whois": "#34a853",
        "email": "#fbbc05",
        "social": "#ea4335",
        "breach": "#ff6d00",
        "tech_stack": "#00bcd4",
    }

    # Severity badges at top
    sev_badges = ""
    sev_config = [("critical", "badge-critical", "Critical"), ("high", "badge-high", "High"),
                   ("medium", "badge-medium", "Medium"), ("low", "badge-low", "Low"),
                   ("info", "badge-none", "Info")]
    for sev_key, badge_cls, label in sev_config:
        count = severity_counts.get(sev_key, 0)
        if count > 0:
            sev_badges += f'<span class="badge {badge_cls}" style="margin-right:4px;">{label}: {count}</span>'

    # Findings by source as collapsible sections
    content = f'<div style="margin-bottom:12px;">{sev_badges}</div>'

    for src in sources_order:
        src_findings = [f for f in findings if f.get("source") == src]
        if not src_findings:
            continue

        label = source_labels.get(src, src)
        color = source_colors.get(src, "#64748b")
        count = source_counts.get(src, 0)

        rows = ""
        for f in src_findings[:25]:
            ftype = _escape_html(f.get("type", ""))
            fval = _escape_html(f.get("value", "")[:100])
            fsev = f.get("severity", "info")
            fconf = f.get("confidence", "medium")
            fctx = _escape_html(f.get("context", "")[:80])
            furl = f.get("url", "")

            sev_colors = {"critical": "#ef4444", "high": "#f59e0b", "medium": "#d97706", "low": "#94a3b8", "info": "#6b7280"}
            sc = sev_colors.get(fsev, "#6b7280")

            url_link = f'<a href="{_escape_html(furl)}" target="_blank" style="color:#06b6d4;font-size:11px;">link</a>' if furl else ""
            rows += f"<tr><td style=\"font-size:11px;color:#94a3b8;\">{ftype}</td>"
            rows += f"<td style=\"font-size:11px;\">{fval}</td>"
            rows += f"<td style=\"font-size:11px;color:#64748b;\">{fctx}</td>"
            rows += f"<td><span style=\"color:{sc};font-size:11px;\">{fsev}</span></td>"
            rows += f"<td style=\"font-size:11px;color:#64748b;\">{fconf}</td>"
            rows += f"<td>{url_link}</td></tr>"

        if len(src_findings) > 25:
            rows += f'<tr><td colspan="6" style="text-align:center;color:#64748b;font-size:11px;">... and {len(src_findings) - 25} more</td></tr>'

        content += f"""
<div style="margin-bottom:16px;">
  <h4 style="color:{color};margin:0 0 6px 0;font-size:14px;">{label} ({count})</h4>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Type</th><th>Value</th><th>Context</th><th>Severity</th><th>Confidence</th><th>URL</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>"""

    return f"""
<div class="section">
  <div class="section-toggle">
    <span>🌐 Advanced OSINT <span class="count">({osint_info.get('total_findings', 0)} findings, {severity_counts.get('critical', 0)} critical)</span></span>
    <span class="arrow">▶</span>
  </div>
  <div class="section-content">
    {content}
  </div>
</div>"""


def _build_waf_section(waf_info: dict) -> str:
    """Build WAF Detection collapsible section."""
    results = waf_info.get("results", {})
    if not results:
        return ""

    url_sections = ""
    for url_str, result in results.items():
        if not result.get("is_protected"):
            continue
        waf_names = [w["name"] for w in result.get("detected_wafs", [])]
        passive = result.get("passive_matches", [])
        active = result.get("active_confirmed", [])

        badges = ""
        for w in waf_names:
            badges += f'<span class="badge badge-sec">{_escape_html(w)}</span>'

        extra = ""
        if passive:
            extra += f'<div style="font-size:11px;color:#64748b;margin-top:4px;">Passive: {_escape_html(", ".join(passive[:3]))}</div>'
        if active:
            extra += f'<div style="font-size:11px;color:#ef4444;margin-top:2px;">Active confirmed: {_escape_html(", ".join(active))}</div>'

        url_sections += f"""
<div class="info-card">
  <div style="font-size:13px;color:#f1f5f9;">{_escape_html(url_str)}</div>
  <div class="tech-list" style="margin-top:6px;">{badges}</div>
  {extra}
</div>"""

    if not url_sections:
        return ""

    return f"""
<div class="section">
  <div class="section-toggle">
    <span>🛡️ WAF Detection &amp; Fingerprinting <span class="count">({waf_info.get('total_protected', 0)} protected, {waf_info.get('total_urls_checked', 0)} checked)</span></span>
    <span class="arrow">▶</span>
  </div>
  <div class="section-content">
    <div class="info-grid">{url_sections}</div>
  </div>
</div>"""
