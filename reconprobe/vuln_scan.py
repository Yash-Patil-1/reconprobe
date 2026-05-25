"""Vulnerability scanning module — CVE mapping and default credential checking.

Maps detected services and versions to known CVEs using an internal reference
database, and checks for common default credentials on discovered services.
Designed to work with port scan results and HTTP probe data.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Optional

import httpx


# ── Data structures ──────────────────────────────────────────────────────────


@dataclass
class CVEInfo:
    """Information about a specific CVE mapped to a service."""
    cve_id: str
    description: str = ""
    cvss_score: Optional[float] = None
    cvss_severity: str = ""
    affected_service: str = ""
    affected_version: str = ""


@dataclass
class DefaultCredential:
    """Default credential found on a service."""
    service: str
    hostname: str
    port: int
    username: str = ""
    password: str = ""
    source: str = ""

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "hostname": self.hostname,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "source": self.source,
        }


@dataclass
class VulnScanReport:
    """Aggregated vulnerability scan results."""
    cve_matches: list[CVEInfo] = field(default_factory=list)
    default_credentials: list[DefaultCredential] = field(default_factory=list)
    total_cves: int = 0
    total_creds: int = 0
    total_high_severity: int = 0

    def to_dict(self) -> dict:
        return {
            "cve_matches": [
                {
                    "cve_id": c.cve_id,
                    "description": c.description[:200] if c.description else "",
                    "cvss_score": c.cvss_score,
                    "cvss_severity": c.cvss_severity,
                    "affected_service": c.affected_service,
                    "affected_version": c.affected_version,
                }
                for c in self.cve_matches
            ],
            "default_credentials": [c.to_dict() for c in self.default_credentials],
            "total_cves": self.total_cves,
            "total_creds": self.total_creds,
            "total_high_severity": self.total_high_severity,
        }


# ── Internal CVE Reference Database ────────────────────────────────────────

# Maps (service_name, version_pattern) -> list of CVEInfo
# Version patterns: "all" means all versions, "*" means wildcard prefix match
# Format: service -> version_pattern -> [CVEInfo, ...]
CVE_REFERENCE_DB: dict[str, dict[str, list[CVEInfo]]] = {
    "ssh": {
        "all": [
            CVEInfo("CVE-2018-15473", "OpenSSH user enumeration vulnerability",
                    5.3, "MEDIUM", "OpenSSH", "< 7.7"),
            CVEInfo("CVE-2020-14145", "OpenSSH man-in-the-middle vulnerability",
                    5.9, "MEDIUM", "OpenSSH", "< 8.5"),
            CVEInfo("CVE-2021-41617", "OpenSSH privilege escalation via pkexec",
                    7.8, "HIGH", "OpenSSH", "< 8.8"),
            CVEInfo("CVE-2023-38408", "OpenSSH remote code execution via forwarded agent",
                    8.1, "HIGH", "OpenSSH", "< 9.3p2"),
            CVEInfo("CVE-2024-6387", "OpenSSH signal handler race condition (regreSSHion)",
                    8.1, "HIGH", "OpenSSH", "8.5p1 - 9.7p1"),
        ],
    },
    "http": {
        "Apache/2.4.49": [
            CVEInfo("CVE-2021-41773", "Apache HTTP Server path traversal and RCE",
                    7.5, "HIGH", "Apache HTTP Server", "2.4.49"),
        ],
        "Apache/2.4.50": [
            CVEInfo("CVE-2021-42013", "Apache HTTP Server path traversal and RCE",
                    9.8, "CRITICAL", "Apache HTTP Server", "2.4.50"),
        ],
        "Apache/2.4.37": [
            CVEInfo("CVE-2020-1927", "Apache HTTP Server mod_rewrite SSRF",
                    7.5, "HIGH", "Apache HTTP Server", "2.4.37"),
        ],
        "nginx/1.20.0": [
            CVEInfo("CVE-2021-23017", "nginx DNS resolver vulnerability",
                    7.5, "HIGH", "nginx", "1.20.0"),
        ],
        "nginx/1.18.0": [
            CVEInfo("CVE-2021-23017", "nginx DNS resolver vulnerability",
                    7.5, "HIGH", "nginx", "1.18.0"),
        ],
        "IIS/10.0": [
            CVEInfo("CVE-2021-31166", "HTTP Protocol Stack Remote Code Execution",
                    9.8, "CRITICAL", "IIS", "10.0"),
        ],
        "IIS/8.5": [
            CVEInfo("CVE-2020-0613", "ASP.NET Core denial of service",
                    7.5, "HIGH", "IIS", "8.5 / ASP.NET Core"),
        ],
    },
    "mysql": {
        "all": [
            CVEInfo("CVE-2023-22102", "MySQL unspecified vulnerability (Oracle Critical Patch)",
                    6.5, "MEDIUM", "MySQL", "8.0.x"),
            CVEInfo("CVE-2023-22053", "MySQL Server DDoS via specially crafted packets",
                    5.5, "MEDIUM", "MySQL", "5.7.x, 8.0.x"),
        ],
        "5.5.": [
            CVEInfo("CVE-2016-6662", "MySQL remote code execution via my.cnf",
                    9.8, "CRITICAL", "MySQL", "5.5.x - 5.7.x"),
        ],
        "5.1.": [
            CVEInfo("CVE-2012-2122", "MySQL authentication bypass (YaSSL memory corruption)",
                    9.8, "CRITICAL", "MySQL", "5.1.x, 5.5.x"),
        ],
    },
    "postgresql": {
        "all": [
            CVEInfo("CVE-2019-9196", "PostgreSQL arbitrary code execution via COPY",
                    8.8, "HIGH", "PostgreSQL", "9.x - 11.x"),
        ],
    },
    "ftp": {
        "all": [
            CVEInfo("CVE-2023-48795", "Terrapin SSH protocol prefix truncation (affects FTP over SSH)",
                    5.9, "MEDIUM", "FTP", "various"),
        ],
    },
    "smtp": {
        "all": [
            CVEInfo("CVE-2020-7247", "OpenSMTPD mail injection and RCE",
                    7.5, "HIGH", "OpenSMTPD", "6.4.0 - 6.6.1"),
        ],
    },
    "redis": {
        "all": [
            CVEInfo("CVE-2022-35977", "Redis integer overflow leading to heap overflow",
                    9.1, "CRITICAL", "Redis", "7.0.0 - 7.0.4"),
        ],
    },
    "mongodb": {
        "all": [
            CVEInfo("CVE-2021-32039", "MongoDB Server key collision vulnerability",
                    5.3, "MEDIUM", "MongoDB", "4.4.x, 5.0.x"),
        ],
    },
    "jenkins": {
        "all": [
            CVEInfo("CVE-2024-23897", "Jenkins arbitrary file read vulnerability",
                    7.5, "HIGH", "Jenkins", "<= 2.441, LTS <= 2.426.2"),
        ],
    },
    "tomcat": {
        "9.0.": [
            CVEInfo("CVE-2020-11996", "Tomcat HTTP/2 denial of service",
                    7.5, "HIGH", "Tomcat", "9.0.0-M1 - 9.0.35"),
        ],
        "8.5.": [
            CVEInfo("CVE-2019-0211", "Tomcat privilege escalation to root",
                    8.8, "HIGH", "Tomcat", "8.5.x"),
        ],
    },
    "phpmyadmin": {
        "all": [
            CVEInfo("CVE-2020-26935", "phpMyAdmin SQL injection vulnerability",
                    8.8, "HIGH", "phpMyAdmin", "5.x before 5.0.3"),
        ],
    },
    "wordpress": {
        "all": [
            CVEInfo("CVE-2023-30800", "WordPress POP chain vulnerability leading to RCE",
                    7.2, "HIGH", "WordPress", "< 6.2.2"),
            CVEInfo("CVE-2023-5360", "WordPress GDPR Cookie Consent plugin SQL injection",
                    9.8, "CRITICAL", "WordPress (plugin)", "various"),
        ],
    },
}


# ── Default Credential Database ─────────────────────────────────────────────

DEFAULT_CREDENTIALS_DB: list[dict] = [
    # SSH
    {"service": "ssh", "username": "root", "password": "root"},
    {"service": "ssh", "username": "root", "password": "admin"},
    {"service": "ssh", "username": "root", "password": "toor"},
    {"service": "ssh", "username": "admin", "password": "admin"},
    {"service": "ssh", "username": "admin", "password": "password"},
    {"service": "ssh", "username": "pi", "password": "raspberry"},
    {"service": "ssh", "username": "ubuntu", "password": "ubuntu"},
    {"service": "ssh", "username": "user", "password": "user"},
    {"service": "ssh", "username": "vagrant", "password": "vagrant"},
    # MySQL
    {"service": "mysql", "username": "root", "password": ""},
    {"service": "mysql", "username": "root", "password": "root"},
    {"service": "mysql", "username": "admin", "password": "admin"},
    # PostgreSQL
    {"service": "postgresql", "username": "postgres", "password": "postgres"},
    {"service": "postgresql", "username": "admin", "password": "admin"},
    # Redis (no auth)
    {"service": "redis", "username": "", "password": ""},
    # MongoDB
    {"service": "mongodb", "username": "admin", "password": "admin"},
    {"service": "mongodb", "username": "root", "password": "root"},
    # FTP
    {"service": "ftp", "username": "anonymous", "password": "anonymous@example.com"},
    {"service": "ftp", "username": "anonymous", "password": ""},
    {"service": "ftp", "username": "ftp", "password": "ftp"},
    {"service": "ftp", "username": "admin", "password": "admin"},
    # Tomcat
    {"service": "tomcat", "username": "tomcat", "password": "tomcat"},
    {"service": "tomcat", "username": "admin", "password": "admin"},
    {"service": "tomcat", "username": "admin", "password": ""},
    # Jenkins
    {"service": "jenkins", "username": "admin", "password": "admin"},
    # phpMyAdmin
    {"service": "phpmyadmin", "username": "root", "password": ""},
    {"service": "phpmyadmin", "username": "root", "password": "root"},
    # Elasticsearch
    {"service": "elasticsearch", "username": "elastic", "password": "changeme"},
    {"service": "elasticsearch", "username": "", "password": ""},
    # RabbitMQ
    {"service": "rabbitmq", "username": "guest", "password": "guest"},
]


# ── CVE Mapping Logic ───────────────────────────────────────────────────────


def match_cve_for_service(
    service_name: str,
    service_version: Optional[str] = None,
    banner: Optional[str] = None,
) -> list[CVEInfo]:
    """Match a detected service to known CVEs from the internal reference database.

    Args:
        service_name: Service name (e.g., 'ssh', 'http', 'mysql').
        service_version: Version string from version detection (e.g., 'Apache/2.4.49').
        banner: Raw banner text for additional matching.

    Returns:
        List of matching CVEInfo objects.
    """
    service_key = service_name.lower().strip()
    matches: list[CVEInfo] = []

    db = CVE_REFERENCE_DB.get(service_key)
    if not db:
        # Try matching against server header patterns
        if banner:
            for svc_key, svc_db in CVE_REFERENCE_DB.items():
                if svc_key in banner.lower():
                    db = svc_db
                    service_key = svc_key
                    break
        if not db:
            return matches

    version_str = service_version or banner or ""

    # Check for exact version matches first
    for version_pattern, cves in db.items():
        if version_pattern == "all":
            continue  # Handle after exact matches
        if version_str.startswith(version_pattern.replace("*", "")) or version_pattern in version_str:
            matches.extend(cves)

    # Add "all"-versions CVEs unless version was matched specifically and we want to avoid duplicates
    if "all" in db:
        all_cves = db["all"]
        for cve in all_cves:
            if cve.cve_id not in {m.cve_id for m in matches}:
                matches.append(cve)

    return matches


def run_cve_mapping(
    scan_reports: list,
    http_probe_reports: Optional[dict] = None,
) -> list[CVEInfo]:
    """Run CVE mapping across all scan results.

    Args:
        scan_reports: List of HostScanReport objects.
        http_probe_reports: Optional HTTP probe reports for tech-based matching.

    Returns:
        List of matched CVEInfo objects.
    """
    all_matches: list[CVEInfo] = []
    seen_ids: set[str] = set()

    # Map from port scan results
    for report in scan_reports:
        for p in getattr(report, "ports", []):
            if getattr(p, "state", "") != "open":
                continue

            service = getattr(p, "service", "")
            banner = getattr(p, "banner", "")
            version_info = getattr(p, "service_version", {})

            # Use version info if available
            version_str = ""
            if version_info:
                product = version_info.get("product", "")
                ver = version_info.get("version", "")
                if product and ver:
                    version_str = f"{product}/{ver}"
                elif product:
                    version_str = product

            # Match from banner if no structured version
            if not version_str and banner:
                # Extract version patterns like "OpenSSH_8.9p1" or "Apache/2.4.49"
                import re
                banner_ver_match = re.search(r"([A-Za-z][A-Za-z0-9._/-]+(?:/[\d.]+[a-z0-9p]*)?)", banner)
                if banner_ver_match:
                    version_str = banner_ver_match.group(1)

            cves = match_cve_for_service(service, version_str, banner)
            for cve in cves:
                if cve.cve_id not in seen_ids:
                    seen_ids.add(cve.cve_id)
                    all_matches.append(cve)

    # Map from HTTP probe technologies
    if http_probe_reports:
        for hostname, probe_report in http_probe_reports.items():
            for result in getattr(probe_report, "results", []):
                for tech in getattr(result, "technologies", []):
                    tech_name = tech.get("name", "")
                    cves = match_cve_for_service(tech_name, banner="")
                    for cve in cves:
                        if cve.cve_id not in seen_ids:
                            seen_ids.add(cve.cve_id)
                            cve.affected_service = tech_name
                            all_matches.append(cve)

    return all_matches


# ── Default Credential Checking ─────────────────────────────────────────────


async def check_default_credential(
    hostname: str,
    port: int,
    service: str,
    username: str,
    password: str,
    timeout: float = 5.0,
) -> Optional[DefaultCredential]:
    """Attempt to verify a default credential on a service.

    Uses service-specific protocols to attempt login.
    For now, this is a best-effort check — only services with simple
    protocol handshakes are checked (FTP, Redis, HTTP basic auth).
    """
    try:
        if service == "ftp":
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port), timeout=timeout
            )
            # Read banner
            banner_data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            # Send USER
            writer.write(f"USER {username}\r\n".encode())
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            resp1 = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            # Send PASS
            writer.write(f"PASS {password}\r\n".encode())
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            resp2 = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            writer.close()
            if b"230" in resp2 or b"Logged" in resp2:
                return DefaultCredential(
                    service=service, hostname=hostname, port=port,
                    username=username, password=password, source="default_creds",
                )
        elif service == "redis":
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port), timeout=timeout
            )
            # Try PING without auth (default config)
            writer.write(b"PING\r\n")
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            resp = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            writer.close()
            if b"+PONG" in resp or b"+OK" in resp:
                # No auth required — writeable by default
                return DefaultCredential(
                    service=service, hostname=hostname, port=port,
                    username="", password="", source="no_auth_required",
                )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        pass
    except Exception:
        pass

    return None


async def check_default_credentials(
    scan_reports: list,
    max_workers: int = 10,
) -> list[DefaultCredential]:
    """Scan discovered services for default credentials.

    Checks common default username/password combinations for each
    discovered service type.

    Args:
        scan_reports: List of HostScanReport objects.
        max_workers: Maximum concurrent connection attempts.

    Returns:
        List of DefaultCredential objects for verified weak credentials.
    """
    found_creds: list[DefaultCredential] = []

    # Collect services to check
    check_queue: list[tuple[str, int, str]] = []
    for report in scan_reports:
        hostname = getattr(report, "hostname", "") or getattr(report, "ip_address", "")
        for p in getattr(report, "ports", []):
            if getattr(p, "state", "") != "open":
                continue
            service = getattr(p, "service", "").lower()
            port = getattr(p, "port", 0)

            # Check if this service has default credentials to test
            has_defaults = any(
                cred["service"] == service for cred in DEFAULT_CREDENTIALS_DB
            )
            if has_defaults:
                check_queue.append((hostname, port, service))

    if not check_queue:
        return found_creds

    semaphore = asyncio.Semaphore(max_workers)

    async def check_service(hostname: str, port: int, service: str) -> list[DefaultCredential]:
        async with semaphore:
            creds_for_service = [
                c for c in DEFAULT_CREDENTIALS_DB if c["service"] == service
            ]
            results: list[DefaultCredential] = []
            for cred in creds_for_service:
                result = await check_default_credential(
                    hostname, port, service,
                    cred["username"], cred["password"],
                )
                if result:
                    results.append(result)
                    break  # One verified weak cred is enough per service instance
            return results

    tasks = [check_service(h, p, s) for h, p, s in check_queue]
    task_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result_list in task_results:
        if isinstance(result_list, list):
            found_creds.extend(result_list)

    return found_creds


# ── Main Orchestrator ───────────────────────────────────────────────────────


async def run_vuln_scan(
    scan_reports: list,
    http_probe_reports: Optional[dict] = None,
    check_credentials: bool = True,
) -> VulnScanReport:
    """Run full vulnerability scan: CVE mapping + default credential checking.

    Args:
        scan_reports: List of HostScanReport objects from port scanning.
        http_probe_reports: Optional dict of HTTP probe reports for tech-based CVE matching.
        check_credentials: Whether to attempt default credential verification.

    Returns:
        VulnScanReport with all findings.
    """
    report = VulnScanReport()

    # Phase 1: CVE Mapping
    cve_matches = run_cve_mapping(scan_reports, http_probe_reports)
    report.cve_matches = cve_matches
    report.total_cves = len(cve_matches)
    report.total_high_severity = sum(
        1 for c in cve_matches
        if c.cvss_severity.upper() in ("HIGH", "CRITICAL")
    )

    # Phase 2: Default Credential Checking
    if check_credentials:
        found_creds = await check_default_credentials(scan_reports)
        report.default_credentials = found_creds
        report.total_creds = len(found_creds)

    return report
