# 🛡️ ReconProbe

**Automated reconnaissance tool for penetration testing**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![Tests](https://github.com/Yash-Patil-1/reconprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/Yash-Patil-1/reconprobe/actions)
[![Codecov](https://codecov.io/gh/Yash-Patil-1/reconprobe/branch/master/graph/badge.svg)](https://codecov.io/gh/Yash-Patil-1/reconprobe)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.9.0-blue)](https://github.com/Yash-Patil-1/reconprobe)

ReconProbe is a comprehensive, modular reconnaissance framework that automates the full penetration testing recon workflow — from subdomain enumeration and port scanning to vulnerability assessment, OSINT gathering, and professional reporting.

---

## Features

### 🔍 Reconnaissance Pipeline (18 Phases)

| Phase | Module | Description |
|-------|--------|-------------|
| 1 | **Subdomain Enumeration** | Passive sources (crt.sh, CertSpotter, VirusTotal, SecurityTrails) + brute-force |
| 2 | **Port Scanning** | Multi-threaded TCP, masscan integration, top-1000 ports, service version detection, OS fingerprinting |
| 3 | **HTTP Probing** | Service discovery, tech fingerprinting (30+ technologies), status code analysis |
| 4 | **Enrichment** | Shodan IP enrichment, NVD CVE lookup for detected technologies |
| 5 | **Web Crawling** | BFS crawler with scope enforcement, depth limiting, interesting finding extraction |
| 6 | **Directory Brute-Force** | Multi-threaded, smart 404 detection, custom extensions |
| 7 | **Screenshots** | Playwright-based headless browser screenshots |
| 8 | **Reporting** | JSON, Markdown, and interactive HTML dashboard with Chart.js |
| 9 | **Vulnerability Scan** | CVE mapping (100+ CVEs, 15+ services) + default credential checking (30+ creds) |
| 10 | **SSL/TLS Audit** | Certificate validation, protocol/cipher scanning, security headers, graded (A-F) |
| 11 | **Subdomain Takeover** | DNS resolution + HTTP signature matching (40+ cloud providers) |
| 12 | **WAF Detection** | Passive header/cookie fingerprinting + active malicious payload probing (15+ WAFs) |
| 13 | **Exploit Suggestions** | 150+ exploit entries mapped to services, Searchsploit integration |
| 14 | **Payload Generation** | Reverse shells: Python, Bash, PowerShell, Netcat, PHP, Perl, Ruby, MSFVenom |
| 15 | **Loot Collection** | Credentials, API keys, tokens, hashes — organized by target/severity |
| 16 | **MSF Script Generation** | Auto-generate Metasploit resource (.rc) scripts from scan results |
| 17 | **Advanced OSINT** | GitHub dorking, Google dorking, email harvesting, WHOIS, social footprinting, breach checks, tech stack OSINT |
| 18 | **Reporting Automation** | CVSS v3.1 scoring, executive summaries, PDF reports, CSV/XLSX exports |

### ⚡ Key Capabilities

- **Batch mode** — Scan multiple targets concurrently from a file
- **Checkpoint/resume** — Interrupted scans pick up where they left off
- **Proxy/Tor support** — Route traffic through HTTP proxies or SOCKS5 (Tor)
- **Rate limiting** — Configurable delay or requests-per-second
- **REST API** — FastAPI-based server for remote scan submission and monitoring
- **Scheduled scanning** — YAML-configurable recurring scans
- **Webhook notifications** — Slack, Discord, and email alerts on scan completion
- **Docker support** — Multi-stage Docker image for easy deployment
- **CI/CD ready** — GitHub Actions workflow with lint, test, type-check, and Docker publish

---

## Installation

### Universal install (works on every OS)

> **⚠️ Note for Kali Linux / Debian 12+:** System-wide `pip install` is blocked to protect the OS.
> Always use a **virtual environment** as shown below.

```bash
# Create and activate a virtual environment
python3 -m venv ~/venvs/reconprobe
source ~/venvs/reconprobe/bin/activate

# Install from PyPI
pip install reconprobe
```

That's it — works on **Linux, macOS, and Windows** with just **Python 3.10+**.

The core install is intentionally lightweight — only pure-Python dependencies (httpx, rich, beautifulsoup4, dnspython, pyyaml). No Docker, no system packages, no browsers required.

> 💡 **Tip:** Add `~/venvs/reconprobe/bin` to your PATH or create an alias so you can run `reconprobe` from anywhere.

#### Install with optional extras

ReconProbe uses **optional dependency groups** so you only install what you need:

```bash
# Activate venv first (if not already active)
source ~/venvs/reconprobe/bin/activate

# Install everything
pip install "reconprobe[full]"

# Or install individual feature groups:
pip install "reconprobe[screenshots]"   # Playwright browser screenshots
pip install "reconprobe[reporting]"    # PDF (fpdf2) + XLSX (openpyxl) exports
pip install "reconprobe[api]"          # FastAPI REST API server
pip install "reconprobe[webhooks]"     # Slack/Discord/Email notifications
```

If you try a feature without the dependency installed, ReconProbe shows a clear install hint:

```
$ reconprobe example.com --serve
Error: FastAPI + uvicorn are required for server mode.
  Install with: pip install reconprobe[api]
```
### From source

```bash
git clone https://github.com/Yash-Patil-1/reconprobe.git
cd reconprobe

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install from local source
pip install -e .              # Core only
# or
pip install -e ".[full]"      # Everything (extras)

# Verify it works
reconprobe --version
```

> 💡 **Tip:** Add `reconprobe/venv/bin` to your PATH or create an alias so you can run `reconprobe` from anywhere.

### Docker (optional)

If you prefer containerized deployment:

```bash
docker pull ghcr.io/yash-patil-1/reconprobe:latest
docker run --rm -v $(pwd)/reports:/reports ghcr.io/yash-patil-1/reconprobe:latest example.com -o /reports
docker run --rm -p 8000:8000 ghcr.io/yash-patil-1/reconprobe:latest --serve
```

### Requirements

- **Python 3.10+** (all platforms)
- **Optional:** `playwright` for screenshots (`playwright install chromium`)
- **Optional:** `fpdf2` for PDF reports
- **Optional:** `openpyxl` for XLSX exports
- **Optional:** `masscan` for high-speed port scanning (Linux only)

---

## Quick Start

```bash
# Basic scan
reconprobe example.com

# Full assessment with all modules enabled
reconprobe example.com \
  --vuln-scan --ssl-audit --takeover --waf-detect \
  --exploit-suggest --payload-gen --loot --msf-gen \
  --osint --html --pdf --csv --xlsx --exec-summary \
  -o ./reports/example_com

# With crawling + directory brute-force
reconprobe example.com --crawl --crawl-depth 3 --dirbuster -o ./reports

# Multi-target batch scan
echo "example.com" > targets.txt
echo "example.org" >> targets.txt
reconprobe --targets-file targets.txt --max-concurrency 5 -o ./batch_reports

# REST API server
reconprobe --serve --port 8000

# Scheduled scanning
cat > schedule.yaml << 'EOF'
schedules:
  - name: "Daily scan"
    target: "example.com"
    interval_hours: 24
    flags:
      vuln_scan: true
      ssl_audit: true
      osint: true
    output_dir: "./reports/daily"
EOF
reconprobe --schedule schedule.yaml
```

---

## CLI Reference

### Basic Options

| Flag | Description |
|------|-------------|
| `domain` | Target domain to scan |
| `-p, --ports` | Ports to scan (`80,443` or `1-1000`) |
| `-o, --output` | Output directory for reports |
| `--no-brute-force` | Skip subdomain brute-force |
| `--wordlist` | Custom subdomain wordlist |
| `--list-ports` | Display common ports reference |
| `-V, --version` | Show version |

### Scanning Performance

| Flag | Default | Description |
|------|---------|-------------|
| `--masscan` | — | Use masscan for high-speed scanning |
| `--masscan-rate` | 1000 | Packets per second for masscan |
| `--max-subdomain-workers` | 50 | Threads for subdomain brute-force |
| `--max-port-workers` | 100 | Threads for port scanning |
| `--port-timeout` | 2.0s | Port scan timeout |
| `--delay` | 0.0s | Delay between requests |
| `--rate-limit` | — | Max requests/second |

### Proxy & Anonymity

| Flag | Description |
|------|-------------|
| `--proxy` | Proxy URL (`http://...`, `socks5://...`) |
| `--tor` | Route through Tor (SOCKS5 localhost:9050) |

### Advanced Scanning

| Flag | Description |
|------|-------------|
| `--version-detection` | Service version fingerprinting |
| `--os-fingerprint` | OS detection via TTL/TCP window |
| `--top-1000` | Scan top 1000 TCP ports |
| `--advanced-subdomains` | Zone transfer + permutations + recursive |
| `--screenshots` | Browser screenshots (requires Playwright) |
| `--crawl` | Web crawling |
| `--dirbuster` | Directory brute-force |

### Vulnerability Assessment

| Flag | Description |
|------|-------------|
| `--vuln-scan` | CVE mapping + default credential check |
| `--no-credential-check` | Skip credential verification |
| `--ssl-audit` | SSL/TLS deep audit |
| `--ssl-ports` | Custom SSL ports (default: 443,8443,9443) |
| `--takeover` | Subdomain takeover detection |
| `--waf-detect` | WAF detection & fingerprinting |

### Exploitation

| Flag | Default | Description |
|------|---------|-------------|
| `--exploit-suggest` | — | Exploit suggestion engine |
| `--payload-gen` | — | Generate reverse shell payloads |
| `--payload-type` | auto | Payload type |
| `--payload-encode` | — | Base64 encode payloads |
| `--loot` | — | Collect loot from scan results |
| `--msf-gen` | — | Generate MSF resource scripts |
| `--lhost` | 127.0.0.1 | Local host for payloads |
| `--lport` | 4444 | Local port for payloads |

### OSINT

| Flag | Description |
|------|-------------|
| `--osint` | Enable all OSINT modules |
| `--github-token` | GitHub PAT for authenticated searches |
| `--no-github-dork` | Skip GitHub dorking |
| `--no-google-dorks` | Skip Google dorking |
| `--no-email-harvest` | Skip email harvesting |
| `--no-whois` | Skip WHOIS lookup |
| `--no-social` | Skip social footprinting |
| `--no-breach-check` | Skip breach database checks |
| `--no-tech-osint` | Skip tech stack OSINT |

### Reporting

| Flag | Description |
|------|-------------|
| `--html` | Interactive HTML dashboard (Chart.js) |
| `--pdf` | Professional PDF report (requires fpdf2) |
| `--csv` | CSV findings export |
| `--xlsx` | XLSX workbook export (requires openpyxl) |
| `--exec-summary` | Executive summary text file |

### Automation

| Flag | Description |
|------|-------------|
| `--serve` | Start REST API server |
| `--host` | API server bind address |
| `--port` | API server port |
| `--schedule` | YAML schedule file for recurring scans |
| `--schedule-once` | Run due scans once and exit |
| `--webhook-slack` | Slack webhook URL |
| `--webhook-discord` | Discord webhook URL |
| `--webhook-email` | SMTP connection string |

---

## REST API

When started with `--serve`, ReconProbe exposes a FastAPI-based REST API.

```bash
reconprobe --serve --host 0.0.0.0 --port 8000
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check with version, uptime, active jobs |
| `POST` | `/scan` | Submit a new scan job |
| `GET` | `/scan/{job_id}` | Get scan job status |
| `GET` | `/scan/{job_id}/result` | Get scan job results |
| `GET` | `/scan/{job_id}/cancel` | Cancel a pending job |
| `GET` | `/jobs` | List recent scan jobs (max 50) |

### Example

```bash
# Submit a scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "flags": {"vuln_scan": true, "osint": true}}'

# Check status
curl http://localhost:8000/scan/{job_id}

# Get results
curl http://localhost:8000/scan/{job_id}/result
```

---

## Scheduled Scanning

Define recurring scans in a YAML file:

```yaml
schedules:
  - name: "Nightly full scan"
    target: "example.com"
    interval_hours: 24
    flags:
      vuln_scan: true
      ssl_audit: true
      takeover: true
      waf_detect: true
      osint: true
      pdf: true
      csv: true
    output_dir: "./reports/example_com"

  - name: "Weekly OSINT"
    target: "example.org"
    interval_hours: 168
    flags:
      osint: true
      no_http_probe: true
      no_brute_force: true
    output_dir: "./reports/example_org"
```

Run the scheduler:

```bash
reconprobe --schedule scan_schedule.yaml
```

---

## Outputs

ReconProbe generates structured reports in multiple formats:

- **JSON** — Complete machine-readable scan data
- **Markdown** — Human-readable formatted report
- **HTML** — Interactive dashboard with Chart.js visualizations (6 chart types, collapsible sections, dark theme)
- **PDF** — Professional security assessment report
- **CSV** — Flat findings export for spreadsheet analysis
- **XLSX** — Multi-sheet workbook with styled headers and severity coloring
- **Executive Summary** — Condensed risk assessment with prioritized recommendations
- **MSF Resource Script** — Ready-to-run Metasploit `.rc` script

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SHODAN_API_KEY` | Shodan API key for IP enrichment |
| `NVD_API_KEY` | NVD API key (higher rate limits) |
| `VT_API_KEY` | VirusTotal API key |
| `ST_API_KEY` | SecurityTrails API key |
| `GITHUB_TOKEN` | GitHub personal access token |

---

## Project Structure

```
reconprobe/
├── reconprobe/
│   ├── __init__.py         # Package metadata, version
│   ├── __main__.py         # python -m reconprobe entry point
│   ├── cli.py              # CLI argument parser & main()
│   ├── runner.py           # 18-phase scan orchestrator
│   ├── subdomain.py        # Subdomain enumeration
│   ├── scanner.py          # Port scanning
│   ├── http_probe.py       # HTTP probing & fingerprinting
│   ├── enrichment.py       # Shodan + NVD enrichment
│   ├── screenshot.py       # Playwright screenshots
│   ├── crawler.py          # Web crawling
│   ├── dirbuster.py        # Directory brute-force
│   ├── vuln_scan.py        # CVE mapping + default creds
│   ├── ssl_audit.py        # SSL/TLS deep audit
│   ├── takeover.py         # Subdomain takeover detection
│   ├── waf_detect.py       # WAF detection & fingerprinting
│   ├── exploit_suggest.py  # Exploit suggestion engine
│   ├── payload_gen.py      # Payload generation
│   ├── loot.py             # Loot collection
│   ├── msf_gen.py          # MSF resource script generator
│   ├── osint.py            # Advanced OSINT
│   ├── reporting.py        # Reporting automation (CVSS, PDF, CSV, XLSX)
│   ├── reporter.py         # JSON + Markdown report builder
│   ├── html_reporter.py    # Interactive HTML dashboard
│   ├── webhook.py          # Slack/Discord/Email notifications
│   ├── scheduler.py        # YAML-based scheduled scanning
│   ├── api.py              # FastAPI REST API
│   ├── batch.py            # Multi-target batch scanning
│   ├── checkpoint.py       # Scan checkpoint/resume
│   └── utils.py            # DNS, validation, common ports
├── tests/                  # Comprehensive test suite (469+ tests)
├── wordlists/
│   ├── subdomains.txt      # Subdomain brute-force wordlist
│   └── paths.txt           # Path discovery wordlist
├── Dockerfile              # Multi-stage Docker build
├── pyproject.toml          # Project configuration
├── MANIFEST.in             # Packaging manifest
├── setup.py                # PyPI setup script
├── Makefile                # Build/test/clean targets
├── CHANGELOG.md            # Release history
├── LICENSE                 # MIT License
└── README.md               # This file
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Author

**Yash Patil** — Cybersecurity Analyst | Penetration Tester

- 📧 yashpatil7714@gmail.com
- 🔗 [LinkedIn](https://www.linkedin.com/in/yash-patil-997357330)
- 🐙 [GitHub](https://github.com/Yash-Patil-1)
