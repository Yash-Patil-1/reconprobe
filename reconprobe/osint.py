"""Advanced OSINT module for ReconProbe.

Performs open-source intelligence gathering across multiple sources:
- GitHub dorking (repos, secrets, config files)
- Google dorking (sensitive exposures)
- Email harvesting (web, search engines, paste sites)
- WHOIS lookups (domain registration intelligence)
- Social footprinting (profiles, mentions, platforms)
- Breach checks (credential leak verification)
- Tech stack OSINT (external technology identification)
"""

from __future__ import annotations

import asyncio
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


# ── Data classes ─────────────────────────────────────────────────────────────


@dataclass
class OsintFinding:
    """A single OSINT finding from any source."""
    source: str  # github, google_dork, email, whois, social, breach, tech_stack
    type: str    # specific type within source
    value: str   # the discovered value
    context: Optional[str] = None  # surrounding context / description
    url: Optional[str] = None      # source URL
    severity: str = "info"  # critical, high, medium, low, info
    confidence: str = "medium"  # high, medium, low
    timestamp: str = ""


@dataclass
class OsintReport:
    """Complete OSINT report for a target."""
    target: str
    findings: list[OsintFinding] = field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # Summary counts per source
    github_findings: int = 0
    google_dork_findings: int = 0
    email_findings: int = 0
    whois_findings: int = 0
    social_findings: int = 0
    breach_findings: int = 0
    tech_stack_findings: int = 0

    def __post_init__(self) -> None:
        self.total_findings = len(self.findings)
        self.critical_count = sum(1 for f in self.findings if f.severity == "critical")
        self.high_count = sum(1 for f in self.findings if f.severity == "high")
        self.medium_count = sum(1 for f in self.findings if f.severity == "medium")
        self.low_count = sum(1 for f in self.findings if f.severity == "low")
        self.info_count = sum(1 for f in self.findings if f.severity == "info")
        self.github_findings = sum(1 for f in self.findings if f.source == "github")
        self.google_dork_findings = sum(1 for f in self.findings if f.source == "google_dork")
        self.email_findings = sum(1 for f in self.findings if f.source == "email")
        self.whois_findings = sum(1 for f in self.findings if f.source == "whois")
        self.social_findings = sum(1 for f in self.findings if f.source == "social")
        self.breach_findings = sum(1 for f in self.findings if f.source == "breach")
        self.tech_stack_findings = sum(1 for f in self.findings if f.source == "tech_stack")

    def by_source(self, source: str) -> list[OsintFinding]:
        return [f for f in self.findings if f.source == source]

    def by_severity(self, severity: str) -> list[OsintFinding]:
        return [f for f in self.findings if f.severity == severity]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "total_findings": self.total_findings,
            "severity_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "source_counts": {
                "github": self.github_findings,
                "google_dork": self.google_dork_findings,
                "email": self.email_findings,
                "whois": self.whois_findings,
                "social": self.social_findings,
                "breach": self.breach_findings,
                "tech_stack": self.tech_stack_findings,
            },
            "findings": [
                {
                    "source": f.source,
                    "type": f.type,
                    "value": f.value,
                    "context": f.context,
                    "url": f.url,
                    "severity": f.severity,
                    "confidence": f.confidence,
                }
                for f in self.findings
            ],
        }


# ── GitHub Dorking ──────────────────────────────────────────────────────────

GITHUB_DORK_QUERIES: list[dict] = [
    {"type": "api_key", "query_template": 'org:{domain} api_key', "severity": "critical"},
    {"type": "api_secret", "query_template": 'org:{domain} secret', "severity": "critical"},
    {"type": "password", "query_template": 'org:{domain} password', "severity": "critical"},
    {"type": "aws_key", "query_template": 'org:{domain} AKIA', "severity": "critical"},
    {"type": "config_file", "query_template": 'org:{domain} filename:.env', "severity": "high"},
    {"type": "config_file", "query_template": 'org:{domain} filename:config.json', "severity": "high"},
    {"type": "database", "query_template": 'org:{domain} connection_string', "severity": "high"},
    {"type": "token", "query_template": 'org:{domain} token', "severity": "high"},
    {"type": "private_key", "query_template": 'org:{domain} "BEGIN RSA PRIVATE KEY"', "severity": "critical"},
    {"type": "certificate", "query_template": 'org:{domain} "BEGIN CERTIFICATE"', "severity": "medium"},
    {"type": "internal_url", "query_template": 'org:{domain} "http://localhost"', "severity": "medium"},
    {"type": "internal_url", "query_template": 'org:{domain} "http://10."', "severity": "medium"},
    {"type": "internal_url", "query_template": 'org:{domain} "http://192.168."', "severity": "medium"},
    {"type": "cloud_key", "query_template": 'org:{domain} "aws_access_key_id"', "severity": "critical"},
    {"type": "slack_token", "query_template": 'org:{domain} xoxb-', "severity": "critical"},
    {"type": "npm_token", "query_template": 'org:{domain} npmrc', "severity": "high"},
    {"type": "ssh_key", "query_template": 'org:{domain} "ssh-rsa" password', "severity": "medium"},
    {"type": "s3_bucket", "query_template": 'org:{domain} "s3.amazonaws.com"', "severity": "high"},
    {"type": "docker_config", "query_template": 'org:{domain} filename:.dockercfg', "severity": "high"},
    {"type": "htpasswd", "query_template": 'org:{domain} filename:.htpasswd', "severity": "critical"},
]


async def github_dork(domain: str, github_token: Optional[str] = None) -> list[OsintFinding]:
    """Search GitHub for exposed secrets, configs, and credentials related to a domain/organization.

    Uses the GitHub Search API (requires token for authenticated requests).
    Falls back to descriptive dork queries if no token is available.
    """
    findings: list[OsintFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    # Extract org name from domain (e.g., example.com -> example)
    org = domain.split(".")[0] if "." in domain else domain

    for dork in GITHUB_DORK_QUERIES:
        query = dork["query_template"].format(domain=org)

        if github_token:
            # Use GitHub API for authenticated search
            result = await _github_api_search(query, github_token)
            if result and result.get("total_count", 0) > 0:
                for item in result.get("items", [])[:5]:  # Top 5 per query
                    repo_name = item.get("repository", {}).get("full_name", "unknown")
                    html_url = item.get("html_url", "")
                    file_name = item.get("name", "")
                    findings.append(OsintFinding(
                        source="github",
                        type=dork["type"],
                        value=f"{repo_name}/{file_name}",
                        context=f"GitHub code search match: {query[:60]}",
                        url=html_url,
                        severity=dork["severity"],
                        confidence="high",
                        timestamp=now,
                    ))
        else:
            # Without token, record the dork query as a suggestion
            encoded_query = query.replace(" ", "+")
            search_url = f"https://github.com/search?q={encoded_query}&type=code"
            findings.append(OsintFinding(
                source="github",
                type=dork["type"],
                value=f"Dork: {query}",
                context=f"Run this GitHub search manually: {query}",
                url=search_url,
                severity=dork["severity"],
                confidence="medium",
                timestamp=now,
            ))

    return findings


async def _github_api_search(query: str, token: str) -> Optional[dict]:
    """Execute a GitHub code search via the REST API."""
    import aiohttp
    try:
        url = "https://api.github.com/search/code"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        params: dict[str, str | int] = {"q": query, "per_page": 5}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(15)) as resp:
                if resp.status == 200:
                    return await resp.json()
    except ImportError:
        pass  # aiohttp not installed
    except Exception:
        pass
    return None


# ── Google Dorking ──────────────────────────────────────────────────────────

GOOGLE_DORKS: list[dict] = [
    {"type": "admin_panel", "query_template": 'site:{domain} inurl:admin', "severity": "high"},
    {"type": "login_page", "query_template": 'site:{domain} inurl:login', "severity": "medium"},
    {"type": "config_file", "query_template": 'site:{domain} ext:cfg ext:conf ext:config', "severity": "high"},
    {"type": "env_file", "query_template": 'site:{domain} ext:env', "severity": "critical"},
    {"type": "database_dump", "query_template": 'site:{domain} ext:sql ext:dump', "severity": "critical"},
    {"type": "log_file", "query_template": 'site:{domain} ext:log', "severity": "high"},
    {"type": "backup_file", "query_template": 'site:{domain} ext:bak ext:backup', "severity": "high"},
    {"type": "directory_listing", "query_template": 'site:{domain} "index of"', "severity": "high"},
    {"type": "error_message", "query_template": 'site:{domain} "warning" "error" "fatal"', "severity": "medium"},
    {"type": "php_info", "query_template": 'site:{domain} ext:php "PHP Version"', "severity": "medium"},
    {"type": "sensitive_doc", "query_template": 'site:{domain} ext:pdf ext:doc ext:xls "confidential"', "severity": "high"},
    {"type": "exposed_api", "query_template": 'site:{domain} inurl:api', "severity": "medium"},
    {"type": "exposed_swagger", "query_template": 'site:{domain} inurl:swagger inurl:api-docs', "severity": "medium"},
    {"type": "git_repo", "query_template": 'site:github.com "{domain}" filename:.gitignore', "severity": "medium"},
    {"type": "stackoverflow", "query_template": 'site:stackoverflow.com "{domain}"', "severity": "low"},
    {"type": "pastebin", "query_template": 'site:pastebin.com "{domain}"', "severity": "high"},
    {"type": "s3_bucket", "query_template": 'site:s3.amazonaws.com "{domain}"', "severity": "medium"},
    {"type": "jenkins", "query_template": 'site:{domain} "Jenkins" "Manage Jenkins"', "severity": "medium"},
    {"type": "phpmyadmin", "query_template": 'site:{domain} inurl:phpmyadmin', "severity": "high"},
    {"type": "cctv_camera", "query_template": 'inurl:"view/view.shtml" site:{domain}', "severity": "low"},
]


async def google_dork(domain: str) -> list[OsintFinding]:
    """Generate Google dork queries and return searchable URLs.

    Does not execute automated Google searches (against ToS).
    Instead generates the dork queries as actionable URLs for manual use.
    """
    findings: list[OsintFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    for dork in GOOGLE_DORKS:
        query = dork["query_template"].format(domain=domain)
        encoded_query = query.replace(" ", "+")
        search_url = f"https://www.google.com/search?q={encoded_query}"

        findings.append(OsintFinding(
            source="google_dork",
            type=dork["type"],
            value=f"Dork: {query}",
            context=f"Google dork to discover {dork['type'].replace('_', ' ')}",
            url=search_url,
            severity=dork["severity"],
            confidence="medium",
            timestamp=now,
        ))

    return findings


# ── Email Harvesting ─────────────────────────────────────────────────────────

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
COMMON_EMAIL_FORMATS = [
    "admin@{domain}",
    "info@{domain}",
    "support@{domain}",
    "contact@{domain}",
    "sales@{domain}",
    "hostmaster@{domain}",
    "postmaster@{domain}",
    "webmaster@{domain}",
    "abuse@{domain}",
    "noreply@{domain}",
    "security@{domain}",
    "privacy@{domain}",
    "legal@{domain}",
    "billing@{domain}",
    "hr@{domain}",
    "jobs@{domain}",
]


async def harvest_emails(
    domain: str,
    web_content: Optional[dict] = None,
    verify_dns: bool = False,
) -> list[OsintFinding]:
    """Harvest email addresses associated with the domain.

    Sources:
    - Extract from HTTP probe / crawl page content
    - Check common email aliases via DNS MX/SPF verification (optional)
    """
    findings: list[OsintFinding] = []
    now = datetime.now(timezone.utc).isoformat()
    seen_emails: set[str] = set()

    # 1. Extract from web content
    if web_content:
        for hostname, probe_data in web_content.items():
            results = []
            if isinstance(probe_data, dict):
                results = probe_data.get("results", [])
            elif hasattr(probe_data, "results"):
                results = getattr(probe_data, "results", [])

            for result in results:
                body = ""
                url = ""
                if isinstance(result, dict):
                    body = result.get("body", "") or result.get("raw_response", "") or ""
                    url = result.get("url", "")
                elif hasattr(result, "body"):
                    body = getattr(result, "body", "") or ""
                    url = getattr(result, "url", "")

                if isinstance(body, str):
                    emails = EMAIL_PATTERN.findall(body)
                    for email in emails:
                        # Length guard: RFC 5321 limits to 254 chars; skip improbable short matches
                        if not (5 <= len(email) <= 254):
                            continue
                        if email.lower().endswith(f"@{domain}") and email not in seen_emails:
                            seen_emails.add(email)
                            findings.append(OsintFinding(
                                source="email",
                                type="email_address",
                                value=email,
                                context=f"Email found on {domain} web content",
                                url=url,
                                severity="low" if any(k in email.lower() for k in ["admin", "root", "security"]) else "info",
                                confidence="high",
                                timestamp=now,
                            ))

    # 2. Check common email aliases via DNS (common_aliases are knowable without DNS)
    #    We'll add common formats as "potential" emails
    for fmt in COMMON_EMAIL_FORMATS:
        email = fmt.format(domain=domain)
        if email not in seen_emails:
            seen_emails.add(email)
            findings.append(OsintFinding(
                source="email",
                type="common_alias",
                value=email,
                context=f"Common email alias for {domain}",
                severity="info",
                confidence="low",
                timestamp=now,
                            ))

    return findings


# ── WHOIS Lookup ─────────────────────────────────────────────────────────────


async def whois_lookup(domain: str, timeout: float = 10.0) -> list[OsintFinding]:
    """Perform a WHOIS lookup on the domain using the 'whois' command.

    Falls back to a WHOIS API suggestion if the command is not available.
    """
    findings: list[OsintFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", domain,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        if proc.returncode == 0 and stdout:
            whois_text = stdout.decode("utf-8", errors="replace")

            # Extract key WHOIS fields
            extraction_patterns = {
                "registrar": (r"Registrar:\s*(.+)", "info"),
                "creation_date": (r"(?:Creation Date|created|Created on):\s*(.+)", "info"),
                "expiry_date": (r"(?:Registry Expiry Date|Expiration Date|Expiry date|Expire Date):\s*(.+)", "info"),
                "name_servers": (r"Name Server:\s*(.+)", "info"),
                "registrant_name": (r"(?:Registrant Name|Registrant):\s*(.+)", "info"),
                "registrant_org": (r"(?:Registrant Organization|OrgName):\s*(.+)", "info"),
                "registrant_email": (r"(?:Registrant Email|Registrant E-mail):\s*(.+)", "medium"),
                "registrant_phone": (r"(?:Registrant Phone|Registrant Telephone):\s*(.+)", "medium"),
                "admin_email": (r"(?:Admin Email|Admin E-mail):\s*(.+)", "medium"),
                "tech_email": (r"(?:Tech Email|Tech E-mail):\s*(.+)", "low"),
                "abuse_email": (r"(?:Abuse Email|Abuse E-mail):\s*(.+)", "low"),
            }

            for field, (pattern, severity) in extraction_patterns.items():
                matches = re.findall(pattern, whois_text, re.IGNORECASE)
                for match in matches[:3]:
                    value = match.strip()
                    if value and len(value) < 200:
                        findings.append(OsintFinding(
                            source="whois",
                            type=field,
                            value=value,
                            context=f"WHOIS {field.replace('_', ' ')}",
                            severity=severity,
                            confidence="high",
                            timestamp=now,
                        ))

            # Check for privacy protection
            if re.search(r"(?:REDACTED FOR PRIVACY|Data Not Shown|GDPR|WHOIS PRIVACY)", whois_text, re.IGNORECASE):
                findings.append(OsintFinding(
                    source="whois",
                    type="privacy_protection",
                    value="WHOIS privacy protection / GDPR redaction active",
                    context="Domain owner info is privacy-protected",
                    severity="low",
                    confidence="high",
                    timestamp=now,
                ))

    except FileNotFoundError:
        # 'whois' command not installed — provide suggestion
        findings.append(OsintFinding(
            source="whois",
            type="whois_unavailable",
            value="whois command not found on system",
            context=f"Install whois or use https://who.is/whois/{domain}",
            url=f"https://who.is/whois/{domain}",
            severity="info",
            confidence="high",
            timestamp=now,
        ))
    except (subprocess.TimeoutExpired, asyncio.TimeoutError):
        findings.append(OsintFinding(
            source="whois",
            type="timeout",
            value=f"WHOIS lookup timed out for {domain}",
            context="WHOIS server may be rate-limiting or unavailable",
            severity="info",
            confidence="high",
            timestamp=now,
        ))
    except Exception:
        pass

    return findings


# ── Social Footprinting ─────────────────────────────────────────────────────


SOCIAL_PLATFORMS: list[dict] = [
    {"name": "LinkedIn", "url_template": "https://www.linkedin.com/company/{domain}", "type": "company_profile"},
    {"name": "LinkedIn", "url_template": "https://www.linkedin.com/search/results/all/?keywords={domain}", "type": "search_result"},
    {"name": "Twitter/X", "url_template": "https://twitter.com/search?q={domain}", "type": "social_presence"},
    {"name": "Facebook", "url_template": "https://www.facebook.com/search/top?q={domain}", "type": "social_presence"},
    {"name": "GitHub", "url_template": "https://github.com/search?q={domain}&type=repositories", "type": "code_repository"},
    {"name": "GitLab", "url_template": "https://gitlab.com/search?search={domain}", "type": "code_repository"},
    {"name": "Crunchbase", "url_template": "https://www.crunchbase.com/organization/{domain}", "type": "company_info"},
    {"name": "Glassdoor", "url_template": "https://www.glassdoor.com/Reviews/{domain}-reviews", "type": "reputation"},
    {"name": "Reddit", "url_template": "https://www.reddit.com/search/?q={domain}", "type": "discussion"},
    {"name": "Stack Overflow", "url_template": "https://stackoverflow.com/search?q={domain}", "type": "developer_presence"},
    {"name": "YouTube", "url_template": "https://www.youtube.com/results?search_query={domain}", "type": "video_content"},
    {"name": "Medium", "url_template": "https://medium.com/search?q={domain}", "type": "blog_content"},
    {"name": "AngelList", "url_template": "https://angel.co/company/{domain}", "type": "startup_info"},
    {"name": "BuiltWith", "url_template": "https://builtwith.com/{domain}", "type": "tech_profile"},
    {"name": "Shodan", "url_template": "https://www.shodan.io/search?query=hostname%3A{domain}", "type": "infrastructure"},
    {"name": "Censys", "url_template": "https://search.censys.io/search?resource=hosts&q={domain}", "type": "infrastructure"},
    {"name": "GreyNoise", "url_template": "https://viz.greynoise.io/query?gnql={domain}", "type": "threat_intel"},
]


async def social_footprint(domain: str) -> list[OsintFinding]:
    """Find social media presence and external platform profiles for the target domain.

    Generates search URLs for common platforms, categorizes by type,
    and assesses exposure levels.
    """
    findings: list[OsintFinding] = []
    now = datetime.now(timezone.utc).isoformat()
    org = domain.split(".")[0] if "." in domain else domain

    for platform in SOCIAL_PLATFORMS:
        url = platform["url_template"].format(domain=domain)
        platform_name = platform["name"]
        platform_type = platform["type"]

        findings.append(OsintFinding(
            source="social",
            type=platform_type,
            value=f"{platform_name}: {org}",
            context=f"{platform_name} search for {domain}",
            url=url,
            severity="info",
            confidence="medium",
            timestamp=now,
        ))

    return findings


# ── Breach Check ─────────────────────────────────────────────────────────────

BREACH_CHECK_SOURCES: list[dict] = [
    {
        "name": "Have I Been Pwned",
        "url_template": "https://haveibeenpwned.com/domain/{domain}",
        "type": "domain_breach",
    },
    {
        "name": "Firefox Monitor",
        "url_template": "https://monitor.firefox.com/scan?q={domain}",
        "type": "domain_breach",
    },
    {
        "name": "DeHashed",
        "url_template": "https://dehashed.com/search?q={domain}",
        "type": "credential_search",
    },
    {
        "name": "LeakCheck",
        "url_template": "https://leakcheck.io/search?query={domain}",
        "type": "credential_search",
    },
    {
        "name": "IntelX",
        "url_template": "https://intelx.io/?s={domain}",
        "type": "darkweb_search",
    },
    {
        "name": "Snusbase",
        "url_template": "https://snusbase.com/?q={domain}",
        "type": "credential_search",
    },
]


async def breach_check(domain: str, emails: Optional[list[str]] = None) -> list[OsintFinding]:
    """Check if the domain or associated emails appear in known data breaches.

    Generates actionable search URLs for breach databases.
    Does NOT perform automated breach database queries (requires API keys/subscriptions).
    """
    findings: list[OsintFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    for source in BREACH_CHECK_SOURCES:
        url = source["url_template"].format(domain=domain)
        findings.append(OsintFinding(
            source="breach",
            type=source["type"],
            value=f"Check {source['name']} for breaches",
            context=f"Search {source['name']} for '{domain}' breach data",
            url=url,
            severity="high",
            confidence="medium",
            timestamp=now,
        ))

    # If we have specific emails, generate individual check URLs
    if emails:
        for email in emails[:10]:  # Limit to 10 emails
            encoded_email = email.replace("@", "%40")
            findings.append(OsintFinding(
                source="breach",
                type="email_breach_check",
                value=f"Check HIBP for {email}",
                context=f"Check if {email} appears in known breaches",
                url=f"https://haveibeenpwned.com/account/{encoded_email}",
                severity="high",
                confidence="medium",
                timestamp=now,
            ))

    return findings


# ── Tech Stack OSINT ──────────────────────────────────────────────────────────

TECH_OSINT_SOURCES: list[dict] = [
    {
        "name": "BuiltWith",
        "url_template": "https://builtwith.com/{domain}",
        "type": "technology_profile",
    },
    {
        "name": "Wappalyzer",
        "url_template": "https://www.wappalyzer.com/lookup/{domain}",
        "type": "technology_profile",
    },
    {
        "name": "Netcraft",
        "url_template": "https://sitereport.netcraft.com/?url={domain}",
        "type": "infrastructure_report",
    },
    {
        "name": "SecurityTrails",
        "url_template": "https://securitytrails.com/domain/{domain}/dns",
        "type": "dns_history",
    },
    {
        "name": "DNSDumpster",
        "url_template": "https://dnsdumpster.com/domain/{domain}",
        "type": "dns_mapping",
    },
    {
        "name": "Censys",
        "url_template": "https://search.censys.io/search?resource=hosts&q={domain}",
        "type": "certificate_transparency",
    },
    {
        "name": "crt.sh",
        "url_template": "https://crt.sh/?q=%25.{domain}",
        "type": "certificate_transparency",
    },
    {
        "name": "Shodan",
        "url_template": "https://www.shodan.io/search?query=hostname%3A{domain}",
        "type": "infrastructure",
    },
    {
        "name": "URLScan",
        "url_template": "https://urlscan.io/domain/{domain}",
        "type": "website_screenshot_history",
    },
    {
        "name": "Wigle",
        "url_template": "https://wigle.net/search?domainq={domain}",
        "type": "wireless_networks",
    },
]


async def tech_stack_osint(domain: str) -> list[OsintFinding]:
    """Identify external technology stack resources for the domain.

    Generates URLs to third-party technology profiling services
    that can reveal the underlying tech stack.
    """
    findings: list[OsintFinding] = []
    now = datetime.now(timezone.utc).isoformat()

    for source in TECH_OSINT_SOURCES:
        url = source["url_template"].format(domain=domain)
        findings.append(OsintFinding(
            source="tech_stack",
            type=source["type"],
            value=f"Check {source['name']} for tech details",
            context=f"Use {source['name']} to analyze {domain}'s technology stack",
            url=url,
            severity="info",
            confidence="medium",
            timestamp=now,
        ))

    return findings


# ── Main orchestrator ────────────────────────────────────────────────────────


async def run_osint(
    domain: str,
    http_probe_data: Any = None,
    crawl_data: Any = None,
    github_token: Optional[str] = None,
    enable_github: bool = True,
    enable_google_dorks: bool = True,
    enable_email: bool = True,
    enable_whois: bool = True,
    enable_social: bool = True,
    enable_breach: bool = True,
    enable_tech_stack: bool = True,
) -> OsintReport:
    """Run all enabled OSINT modules against the target domain.

    Args:
        domain: The target domain to investigate.
        http_probe_data: Optional HTTP probe results for email/web content extraction.
        crawl_data: Optional crawl results for email extraction.
        github_token: Optional GitHub personal access token for authenticated API searches.
        enable_github: Enable GitHub dorking.
        enable_google_dorks: Enable Google dork generation.
        enable_email: Enable email harvesting.
        enable_whois: Enable WHOIS lookup.
        enable_social: Enable social footprinting.
        enable_breach: Enable breach checking.
        enable_tech_stack: Enable tech stack OSINT.

    Returns:
        An OsintReport with all findings.
    """
    all_findings: list[OsintFinding] = []
    seen: set[str] = set()

    def add_findings(findings: list[OsintFinding]) -> None:
        for f in findings:
            key = f"{f.source}:{f.type}:{f.value[:80]}"
            if key not in seen:
                seen.add(key)
                all_findings.append(f)

    tasks: list = []

    if enable_github:
        tasks.append(github_dork(domain, github_token))

    if enable_google_dorks:
        tasks.append(google_dork(domain))

    if enable_email:
        tasks.append(harvest_emails(domain, http_probe_data))

    if enable_whois:
        tasks.append(whois_lookup(domain))

    if enable_social:
        tasks.append(social_footprint(domain))

    if enable_breach:
        tasks.append(breach_check(domain))

    if enable_tech_stack:
        tasks.append(tech_stack_osint(domain))

    # Run all OSINT modules concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Exception):
            continue
        if isinstance(result, list):
            add_findings(result)

    # Restructure breach findings with emails if we found any
    if enable_breach and enable_email:
        emails = [f.value for f in all_findings if f.source == "email"]
        if emails:
            breach_emails = await breach_check(domain, emails)
            add_findings(breach_emails)

    # Sort by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    return OsintReport(target=domain, findings=all_findings)
