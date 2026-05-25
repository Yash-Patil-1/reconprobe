# Changelog

All notable changes to ReconProbe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-05-25

### Added

- **Phase 8: Polish & Distribution**
  - Comprehensive README with full CLI reference, API docs, and examples
  - PyPI packaging (setup.py + MANIFEST.in for backward compatibility)
  - Makefile with build/test/clean/publish targets
  - CHANGELOG.md for release tracking
  - Git repository initialization

### Fixed

- SSL/TLS audit: suppressed Python 3.13 deprecation warnings for TLS 1.0/1.1 version constants
- Version bumped to 1.0.0 for first stable release

---

## [0.7.0] — 2026-05-25

### Added

- **Phase 7: CI/CD & Automation**
  - FastAPI REST API (`--serve`) with async job queue
  - YAML-based scheduled scanning (`--schedule`)
  - Webhook notifications (Slack, Discord, Email)
  - GitHub Actions CI workflow (lint, test, type-check, Docker publish)
  - Multi-stage Dockerfile for lean production images

---

## [0.6.0] — 2026-05-24

### Added

- **Phase 6: Reporting Automation**
  - CVSS v3.1 base score calculator (all 8 metrics, vector string generation)
  - Professional PDF report generation (fpdf2)
  - CSV and XLSX findings export with multi-sheet workbooks
  - Executive summary with risk assessment and prioritized recommendations
  - Scan timeline and metrics

---

## [0.5.0] — 2026-05-24

### Added

- **Phase 5: Advanced OSINT**
  - GitHub dorking (20 query patterns)
  - Google dorking (20 query patterns)
  - Email harvesting + alias generation
  - WHOIS lookups
  - Social footprinting (17 platforms)
  - Breach database checks (6 sources)
  - Tech stack OSINT (10 external sources)
  - 55 unit tests

---

## [0.4.0] — 2026-05-24

### Added

- **Phase 4: Exploitation Integration**
  - Exploit suggestion engine (150+ entries, 30+ services)
  - Reverse shell & payload generator (Python, Bash, PowerShell, Netcat, PHP, Perl, Ruby, MSFVenom)
  - Loot collection & organization (credentials, API keys, tokens, hashes)
  - Metasploit resource script (.rc) generator
  - Unit tests for all Phase 4 modules

---

## [0.3.0] — 2026-05-23

### Added

- **Phase 3: Vulnerability Assessment**
  - Vulnerability scanning: CVE mapping for detected services (100+ CVEs, 15+ services)
  - Default credential checking with live protocol verification (30+ creds)
  - SSL/TLS deep audit: certificate analysis, protocol/cipher scanning, security headers, graded A-F
  - Subdomain takeover detection: DNS + HTTP signature matching (40+ cloud providers)
  - WAF detection & fingerprinting: passive header analysis + active probing (15+ WAFs)
  - Pipeline extended to 16 phases
  - HTML dashboard updated with Vuln CVE chart and summary cards

---

## [0.2.0] — 2026-05-23

### Added

- **Phase 2: Advanced Features**
  - Web crawling (BFS, scope enforcement, depth limiting, interesting finding extraction)
  - Directory brute-force (multi-threaded, smart 404 detection, custom extensions)
  - API integrations: Shodan IP enrichment + NVD CVE lookup
  - Interactive HTML dashboard with Chart.js (6 chart types, collapsible sections, dark theme)
  - Advanced subdomain techniques: zone transfer, permutation engine, recursive discovery
  - Service version detection + OS fingerprinting via TTL/TCP window heuristics
  - Quality of Life: rate limiting, proxy/Tor support, checkpoint/resume, multi-target batch mode
  - Curated wordlists (subdomains.txt, paths.txt)

---

## [0.1.0] — 2026-05-22

### Added

- **Phase 1: Core Infrastructure**
  - CLI entry point with argparse + Rich formatting
  - 9-phase scan orchestrator with progress bars
  - Subdomain enumeration (crt.sh, CertSpotter, VirusTotal, SecurityTrails, brute-force)
  - Port scanning (multi-threaded TCP + masscan integration)
  - HTTP probing with technology fingerprinting (30+ technologies)
  - Playwright-based screenshot capture
  - JSON + Markdown report generation
  - Domain validation, DNS resolution, banner grabbing utilities
  - Initial project structure and packaging

---

[1.0.0]: https://github.com/Yash-Patil-1/reconprobe/releases/tag/v1.0.0
[0.7.0]: https://github.com/Yash-Patil-1/reconprobe/releases/tag/v0.7.0
[0.6.0]: https://github.com/Yash-Patil-1/reconprobe/releases/tag/v0.6.0
[0.5.0]: https://github.com/Yash-Patil-1/reconprobe/releases/tag/v0.5.0
[0.4.0]: https://github.com/Yash-Patil-1/reconprobe/releases/tag/v0.4.0
[0.3.0]: https://github.com/Yash-Patil-1/reconprobe/releases/tag/v0.3.0
[0.2.0]: https://github.com/Yash-Patil-1/reconprobe/releases/tag/v0.2.0
[0.1.0]: https://github.com/Yash-Patil-1/reconprobe/releases/tag/v0.1.0
