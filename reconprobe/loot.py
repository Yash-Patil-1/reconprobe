"""Loot collection and organization for ReconProbe.

Harvests discovered credentials, API keys, tokens, hashes, and other valuable
artifacts from scan results and organizes them by target, type, and severity.
"""

from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class LootItem:
    """A single piece of loot discovered during scanning."""
    type: str  # credential, api_key, token, hash, endpoint, certificate, email, internal_host
    source: str  # which module discovered this (vuln_scan, http_probe, crawl, etc.)
    target: str  # the host/subdomain it was found on
    data: Any  # the actual loot data (string, dict, etc.)
    severity: str = "info"  # critical, high, medium, low, info
    description: Optional[str] = None
    port: Optional[int] = None
    path: Optional[str] = None
    discovered_at: str = ""


@dataclass
class LootReport:
    """Organized collection of all loot from a scan."""
    target: str
    items: list[LootItem] = field(default_factory=list)
    total_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    def __post_init__(self) -> None:
        self.total_count = len(self.items)
        self.critical_count = sum(1 for i in self.items if i.severity == "critical")
        self.high_count = sum(1 for i in self.items if i.severity == "high")
        self.medium_count = sum(1 for i in self.items if i.severity == "medium")
        self.low_count = sum(1 for i in self.items if i.severity == "low")
        self.info_count = sum(1 for i in self.items if i.severity == "info")

    def by_type(self, loot_type: str) -> list[LootItem]:
        return [i for i in self.items if i.type == loot_type]

    def by_severity(self, severity: str) -> list[LootItem]:
        return [i for i in self.items if i.severity == severity]

    def by_source(self, source: str) -> list[LootItem]:
        return [i for i in self.items if i.source == source]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "total_count": self.total_count,
            "severity_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "items": [
                {
                    "type": item.type,
                    "source": item.source,
                    "target": item.target,
                    "data": str(item.data) if not isinstance(item.data, (dict, list)) else item.data,
                    "severity": item.severity,
                    "description": item.description,
                    "port": item.port,
                    "path": item.path,
                }
                for item in self.items
            ],
        }


# ── Credential / API key / token patterns ───────────────────────────────────

CREDENTIAL_PATTERNS: list[tuple[str, str, str]] = [
    ("api_key", r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_-]{16,64})['\"]?", "high"),
    ("api_secret", r"(?i)(?:api[_-]?secret|apisecret)\s*[=:]\s*['\"]?([A-Za-z0-9_-]{16,128})['\"]?", "critical"),
    ("aws_key", r"(?i)(AKIA[0-9A-Z]{16})", "critical"),
    ("aws_secret", r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*['\"]?([A-Za-z0-9+/]{40})['\"]?", "critical"),
    ("github_token", r"(?i)(ghp_[A-Za-z0-9]{36})", "critical"),
    ("github_token_old", r"(?i)(gho_[A-Za-z0-9]{36})", "critical"),
    ("gitlab_token", r"(?i)(glpat-[A-Za-z0-9_-]{20,})", "critical"),
    ("slack_token", r"(?i)(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24})", "critical"),
    ("discord_token", r"(?i)([MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27})", "critical"),
    ("jwt_token", r"(?i)(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})", "high"),
    ("google_api_key", r"(?i)(AIza[0-9A-Za-z_-]{35})", "high"),
    ("facebook_token", r"(?i)(EAACEdEose0cBA[0-9A-Za-z]{30,})", "critical"),
    ("twitter_token", r"(?i)([1-9][0-9]+-[0-9A-Za-z]{40})", "critical"),
    ("heroku_api_key", r"(?i)([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})", "critical"),
    ("password_in_url", r"(?i)(?:password|pass|pwd)\s*[=:]\s*['\"]?([^&\s'\"]{4,50})['\"]?", "critical"),
    ("private_key_header", r"(?i)-{3,}BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-{3,}", "critical"),
    ("auth_basic", r"(?i)(?:authorization|auth)\s*:\s*basic\s+([A-Za-z0-9+/=]{10,})", "critical"),
    ("bearer_token", r"(?i)(?:bearer|token)\s+([A-Za-z0-9_.-]{10,200})", "critical"),
    ("mongo_uri", r"(?i)mongodb(?:\+srv)?://[^/\s]+:[^@\s]+@", "critical"),
    ("mysql_uri", r"(?i)mysql://[^:]+:[^@]+@", "critical"),
    ("postgres_uri", r"(?i)postgres(?:ql)?://[^:]+:[^@]+@", "critical"),
    ("redis_uri", r"(?i)redis://[^:]+:[^@]+@", "critical"),
    ("ssh_key", r"(?i)ssh-rsa\s+AAAA[0-9A-Za-z+/]+[=]{0,3}\s+", "medium"),
    ("slack_webhook", r"(?i)hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}", "critical"),
]

# ── Email pattern ────────────────────────────────────────────────────────────

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# ── Internal IP / host patterns ──────────────────────────────────────────────

INTERNAL_IP_PATTERN = re.compile(r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})")


def _collect_from_vuln_scan(vuln_scan_data: Any, target: str) -> list[LootItem]:
    """Extract credentials found by the vuln_scan module."""
    items: list[LootItem] = []
    now = datetime.now(timezone.utc).isoformat()

    # Check for default credentials found
    if hasattr(vuln_scan_data, "default_credentials"):
        for cred in vuln_scan_data.default_credentials:
            items.append(LootItem(
                type="credential",
                source="vuln_scan",
                target=target,
                data={
                    "service": getattr(cred, "service", ""),
                    "username": getattr(cred, "username", ""),
                    "password": getattr(cred, "password", ""),
                    "port": getattr(cred, "port", None),
                    "status": getattr(cred, "status", ""),
                },
                severity="critical",
                description=f"Default credentials for {getattr(cred, 'service', 'unknown')}",
                port=getattr(cred, "port", None),
                discovered_at=now,
            ))

    # Handle dict-based data (primary path from runner)
    if isinstance(vuln_scan_data, dict):
        creds = vuln_scan_data.get("default_credentials", [])
        for cred in creds:
            items.append(LootItem(
                type="credential",
                source="vuln_scan",
                target=target,
                data={
                    "service": cred.get("service", ""),
                    "username": cred.get("username", ""),
                    "password": cred.get("password", ""),
                    "port": cred.get("port"),
                    "status": cred.get("status", ""),
                },
                severity="critical",
                description=f"Default credentials for {cred.get('service', 'unknown')}",
                port=cred.get("port"),
                discovered_at=now,
            ))

    return items


def _collect_from_http_probe(http_probe_data: Any, target: str) -> list[LootItem]:
    """Extract loot from HTTP probe responses."""
    items: list[LootItem] = []
    now = datetime.now(timezone.utc).isoformat()

    results: list = []
    if isinstance(http_probe_data, dict):
        results = http_probe_data.get("results", [])
    elif hasattr(http_probe_data, "results"):
        results = http_probe_data.results

    for result in results:
        body = ""
        headers: dict = {}
        url = ""
        port = None

        if isinstance(result, dict):
            body = result.get("body", "") or result.get("raw_response", "") or ""
            headers = result.get("headers", {})
            url = result.get("url", "")
            port = result.get("port")
        elif hasattr(result, "body"):
            body = getattr(result, "body", "") or ""
            headers = getattr(result, "headers", {}) or {}
            url = getattr(result, "url", "")
            port = getattr(result, "port", None)

        # Combine body + response text + URL for pattern matching
        text_content = body
        if isinstance(text_content, str):
            # Scan for credentials/keys in page content
            for loot_type, pattern_str, severity in CREDENTIAL_PATTERNS:
                matches = re.findall(pattern_str, text_content)
                for match in matches[:3]:  # Limit to 3 per pattern per page
                    # Clean up the match
                    if isinstance(match, tuple):
                        match = match[0]
                    items.append(LootItem(
                        type=loot_type,
                        source="http_probe",
                        target=target,
                        data=match[:100],  # Truncate long matches
                        severity=severity,
                        description=f"{loot_type} found in page content",
                        port=port,
                        path=url,
                        discovered_at=now,
                    ))

            # Find emails
            emails = EMAIL_PATTERN.findall(text_content)
            for email in list(set(emails))[:10]:
                items.append(LootItem(
                    type="email",
                    source="http_probe",
                    target=target,
                    data=email,
                    severity="low" if "admin" in email.lower() or "root" in email.lower() else "info",
                    description=f"Email address: {email}",
                    port=port,
                    path=url,
                    discovered_at=now,
                ))

            # Find internal IPs
            internal_ips = INTERNAL_IP_PATTERN.findall(text_content)
            for ip in list(set(internal_ips))[:10]:
                items.append(LootItem(
                    type="internal_host",
                    source="http_probe",
                    target=target,
                    data=ip,
                    severity="medium",
                    description=f"Internal IP address disclosed: {ip}",
                    port=port,
                    path=url,
                    discovered_at=now,
                ))

    return items


def _collect_from_crawl(crawl_data: Any, target: str) -> list[LootItem]:
    """Extract loot from crawl results."""
    items: list[LootItem] = []
    now = datetime.now(timezone.utc).isoformat()

    pages: list = []
    if isinstance(crawl_data, dict):
        pages = crawl_data.get("pages", []) or crawl_data.get("results", [])
    elif hasattr(crawl_data, "pages"):
        pages = crawl_data.pages
    elif isinstance(crawl_data, list):
        pages = crawl_data

    for page in pages:
        url = ""
        body = ""
        forms: list = []

        if isinstance(page, dict):
            url = page.get("url", "")
            body = page.get("body", "") or page.get("raw_body", "") or ""
            forms = page.get("forms", [])
        elif hasattr(page, "url"):
            url = getattr(page, "url", "")
            body = getattr(page, "body", "") or ""
            forms = getattr(page, "forms", []) or []

        # Scan for credentials/keys in body
        text = body if isinstance(body, str) else ""
        for loot_type, pattern_str, severity in CREDENTIAL_PATTERNS:
            matches = re.findall(pattern_str, text)
            for match in matches[:2]:
                if isinstance(match, tuple):
                    match = match[0]
                items.append(LootItem(
                    type=loot_type,
                    source="crawl",
                    target=target,
                    data=match[:100],
                    severity=severity,
                    description=f"{loot_type} found in crawler page",
                    path=url,
                    discovered_at=now,
                ))

        # Extract form action URLs with password fields (potential login pages)
        for form in forms:
            form_action = ""
            form_inputs: list = []
            if isinstance(form, dict):
                form_action = form.get("action", "")
                form_inputs = form.get("inputs", [])
            elif hasattr(form, "action"):
                form_action = getattr(form, "action", "")
                form_inputs = getattr(form, "inputs", [])

            has_password = False
            for inp in form_inputs:
                inp_type = ""
                if isinstance(inp, dict):
                    inp_type = inp.get("type", "")
                elif hasattr(inp, "type"):
                    inp_type = getattr(inp, "type", "")
                if inp_type == "password":
                    has_password = True
                    break

            if has_password:
                items.append(LootItem(
                    type="endpoint",
                    source="crawl",
                    target=target,
                    data=form_action or url,
                    severity="high",
                    description=f"Login form found at {form_action or url}",
                    path=url,
                    discovered_at=now,
                ))

    return items


def _collect_from_enrichment(enrichment_data: Any, target: str) -> list[LootItem]:
    """Extract loot from enrichment data."""
    items: list[LootItem] = []
    now = datetime.now(timezone.utc).isoformat()

    # Check for Shodan CVEs
    if isinstance(enrichment_data, dict):
        shodan_vulns = enrichment_data.get("shodan", {}).get("vulns", []) or []
        for vuln in shodan_vulns:
            if isinstance(vuln, dict):
                cve_id = vuln.get("cve_id", "") or vuln.get("id", "")
                if cve_id:
                    items.append(LootItem(
                        type="vulnerability",
                        source="enrichment",
                        target=target,
                        data=cve_id,
                        severity="high" if vuln.get("cvss", 0) >= 7 else "medium",
                        description=f"Known vulnerability: {cve_id} (CVSS: {vuln.get('cvss', 'N/A')})",
                        discovered_at=now,
                    ))

    # Check for NVD CVEs
    if isinstance(enrichment_data, dict):
        nvd_cves = enrichment_data.get("nvd_cves", []) or []
        for cve in nvd_cves:
            if isinstance(cve, dict):
                cve_id = cve.get("id", "") or cve.get("cve_id", "")
                if cve_id:
                    items.append(LootItem(
                        type="vulnerability",
                        source="enrichment",
                        target=target,
                        data=cve_id,
                        severity="high" if cve.get("cvss_score", 0) >= 7 else "medium",
                        description=f"NVD CVE: {cve_id} (Score: {cve.get('cvss_score', 'N/A')})",
                        discovered_at=now,
                    ))

    return items


def _collect_from_takeover(takeover_data: Any, target: str) -> list[LootItem]:
    """Extract loot from takeover detection results."""
    items: list[LootItem] = []
    now = datetime.now(timezone.utc).isoformat()

    results: list = []
    if isinstance(takeover_data, dict):
        results = takeover_data.get("results", [])
    elif hasattr(takeover_data, "results"):
        results = takeover_data.results

    for result in results:
        subdomain = ""
        vulnerable = False
        service = ""
        confidence = ""

        if isinstance(result, dict):
            subdomain = result.get("subdomain", "")
            vulnerable = result.get("vulnerable", False)
            service = result.get("service", "")
            confidence = result.get("confidence", "")
        elif hasattr(result, "subdomain"):
            subdomain = getattr(result, "subdomain", "")
            vulnerable = getattr(result, "vulnerable", False)
            service = getattr(result, "service", "")
            confidence = getattr(result, "confidence", "")

        if vulnerable and subdomain:
            items.append(LootItem(
                type="takeover",
                source="takeover",
                target=subdomain,
                data={"service": service, "confidence": confidence, "subdomain": subdomain},
                severity="critical",
                description=f"Subdomain takeover: {subdomain} ({service})",
                discovered_at=now,
            ))

    return items


def collect_loot(
    target: str,
    vuln_scan_data: Any = None,
    http_probe_data: Any = None,
    crawl_data: Any = None,
    enrichment_data: Any = None,
    takeover_data: Any = None,
) -> LootReport:
    """Collect and organize loot from all scan data sources.

    Args:
        target: The primary target domain.
        vuln_scan_data: Data from vulnerability scan module (default credentials).
        http_probe_data: Data from HTTP probing.
        crawl_data: Data from web crawler.
        enrichment_data: Data from Shodan/NVD enrichment.
        takeover_data: Data from subdomain takeover detection.

    Returns:
        A LootReport with all discovered items organized by severity.
    """
    all_items: list[LootItem] = []
    seen: set[str] = set()

    def add_items(items: list[LootItem]) -> None:
        for item in items:
            key = f"{item.type}:{item.target}:{str(item.data)[:50]}"
            if key not in seen:
                seen.add(key)
                all_items.append(item)

    if vuln_scan_data:
        add_items(_collect_from_vuln_scan(vuln_scan_data, target))
    if http_probe_data:
        add_items(_collect_from_http_probe(http_probe_data, target))
    if crawl_data:
        add_items(_collect_from_crawl(crawl_data, target))
    if enrichment_data:
        add_items(_collect_from_enrichment(enrichment_data, target))
    if takeover_data:
        add_items(_collect_from_takeover(takeover_data, target))

    # Sort by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_items.sort(key=lambda i: severity_order.get(i.severity, 99))

    return LootReport(target=target, items=all_items)
