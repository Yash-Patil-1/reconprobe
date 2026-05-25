"""Advanced subdomain enumeration techniques.

Features:
- DNS Zone Transfer (AXFR) — attempt to pull full zone from misconfigured nameservers
- Permutation Engine — generate mutations from known subdomains (word insertion,
  number iteration, hyphenation, leetspeak, prefix/suffix, word substitution)
- Recursive Discovery — run passive sources on newly discovered subdomains at
  multiple depth levels to uncover nested subdomains
"""

from __future__ import annotations

import asyncio
import itertools
import json
import random
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

import httpx

from reconprobe.utils import is_valid_domain, resolve_hostname

# ─── Permutation Rules ───────────────────────────────────────────────────────

# Common environment/enumeration suffixes to append/prepend
PERMUTATION_KEYWORDS = [
    "dev", "staging", "stage", "prod", "production", "test", "testing",
    "uat", "qa", "beta", "alpha", "demo", "sandbox", "lab", "internal",
    "external", "public", "private", "backup", "old", "new", "temp",
    "admin", "api", "app", "web", "portal", "secure", "origin", "cdn",
    "static", "assets", "media", "files", "uploads", "downloads",
    "docs", "help", "support", "status", "metrics", "monitor", "logs",
    "db", "database", "sql", "cache", "redis", "mq", "queue", "worker",
    "ci", "cd", "build", "jenkins", "gitlab", "jira", "wiki",
    "vpn", "proxy", "relay", "mail", "smtp", "pop3", "imap",
    "ns1", "ns2", "dns1", "dns2", "mx", "mx1", "mx2",
    "auth", "login", "register", "sso", "oauth", "saml",
    "grafana", "prometheus", "kibana", "elastic", "kafka",
    "socket", "ws", "wss", "stream", "rtmp", "rtsp",
    "v1", "v2", "v3", "v4", "api-v1", "api-v2",
    "graphql", "rest", "soap", "grpc",
]

# Leetspeak / keyboard proximity substitutions
LEETSPEAK_MAP: dict[str, list[str]] = {
    "a": ["4", "@"],
    "b": ["8"],
    "e": ["3"],
    "g": ["9", "6"],
    "i": ["1", "!"],
    "l": ["1", "|"],
    "o": ["0"],
    "s": ["5", "$"],
    "t": ["7"],
    "z": ["2"],
}

# Common numeric ranges to iterate
NUMERIC_RANGES: list[range] = [
    range(1, 11),   # 1-10
    range(0, 100, 10),  # 0, 10, 20, ..., 90
]


@dataclass
class ZoneTransferResult:
    """Result of a DNS zone transfer attempt."""
    nameserver: str
    success: bool
    records: list[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class PermutationReport:
    """Results from the permutation engine."""
    total_generated: int = 0
    total_resolved: int = 0
    new_subdomains: list[str] = field(default_factory=list)


@dataclass
class AdvancedSubdomainReport:
    """Aggregated report of advanced enumeration techniques."""
    zone_transfer_results: list[ZoneTransferResult] = field(default_factory=list)
    permutation_report: Optional[PermutationReport] = None
    recursive_results: dict[str, list[str]] = field(default_factory=dict)  # depth -> subdomains
    total_new_subdomains: int = 0


# ─── Helpers ─────────────────────────────────────────────────────────────────

def resolve_nameservers(domain: str) -> list[str]:
    """Resolve NS records for a domain to IP addresses."""
    ns_ips: list[str] = []
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "NS")
        for rdata in answers:
            ns_hostname = str(rdata.target).rstrip(".")
            try:
                ns_ip = socket.getaddrinfo(ns_hostname, 53)[0][4][0]
                ns_ips.append(ns_ip)
            except (socket.gaierror, OSError, IndexError):
                pass
    except ImportError:
        # dnspython not installed
        pass
    except Exception as e:
        # DNS resolution failed
        pass
    return ns_ips


def attempt_zone_transfer_sync(domain: str, nameserver: str) -> ZoneTransferResult:
    """Attempt a DNS zone transfer (AXFR) from a single nameserver."""
    import dns.query
    import dns.zone
    import dns.exception

    try:
        zone = dns.zone.Zone(domain)
        dns.query.inbound_xfr(nameserver, zone, timeout=10.0)
        records: list[str] = []
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    record_str = f"{name} {rdataset.rdtype} {rdata}"
                    records.append(record_str)
        return ZoneTransferResult(
            nameserver=nameserver,
            success=bool(records),
            records=records[:500],  # Limit output
        )
    except (dns.exception.DNSException, OSError, ConnectionError) as e:
        return ZoneTransferResult(
            nameserver=nameserver,
            success=False,
            error=str(e),
        )


async def attempt_zone_transfer(domain: str) -> list[ZoneTransferResult]:
    """Attempt zone transfer from all discovered nameservers."""
    ns_ips = resolve_nameservers(domain)
    if not ns_ips:
        return []

    loop = asyncio.get_running_loop()
    results = []
    for ns in ns_ips:
        result = await loop.run_in_executor(
            None, attempt_zone_transfer_sync, domain, ns
        )
        results.append(result)

    return results


# ─── Permutation Engine ──────────────────────────────────────────────────────

def apply_leetseak(word: str) -> list[str]:
    """Generate leetspeak variations of a word."""
    variations: list[str] = [word]

    # Find positions of leetspeak-able characters
    positions: list[tuple[int, list[str]]] = []
    for i, char in enumerate(word.lower()):
        if char in LEETSPEAK_MAP:
            positions.append((i, LEETSPEAK_MAP[char]))

    if not positions:
        return variations

    # Generate combinations (limit to avoid explosion)
    limited_positions = positions[:3]  # Max 3 substitutions at a time
    for r in range(1, len(limited_positions) + 1):
        for combo in itertools.combinations(limited_positions, r):
            for replacements in itertools.product(*[p[1] for p in combo]):
                word_list = list(word)
                for (idx, _), repl in zip(combo, replacements):
                    word_list[idx] = repl
                variations.append("".join(word_list))

    return deduplicate(variations)


def generate_prefixed(subdomain_prefix: str) -> list[str]:
    """Generate words with common prefixes prepended."""
    prefixes = ["dev-", "staging-", "test-", "api-", "admin-", "pre-", "new-",
                "backup-", "old-", "secure-", "vpn-", "mail-", "beta-"]
    return [f"{p}{subdomain_prefix}" for p in prefixes]


def generate_suffixed(subdomain_prefix: str) -> list[str]:
    """Generate words with common suffixes appended."""
    suffixes = ["-dev", "-staging", "-test", "-api", "-admin", "-backup",
                "-old", "-new", "-beta", "-uat", "-qa", "-internal", "-external"]
    return [f"{subdomain_prefix}{s}" for s in suffixes]


def generate_numbered(subdomain_prefix: str) -> list[str]:
    """Generate words with numeric suffixes."""
    results: list[str] = []
    for n in range(1, 21):  # 1-20
        results.append(f"{subdomain_prefix}{n}")
    return results


def generate_permutations(subdomains: list[str], domain: str) -> set[str]:
    """Generate permuted subdomain candidates from known subdomains.

    Applies multiple mutation rules:
    - Prefix/suffix insertion with common keywords
    - Number iteration
    - Leetspeak character substitution
    - Hyphenation (insert hyphens between compound words)
    """
    candidates: set[str] = set()

    for sub in subdomains:
        # Strip the domain suffix to get the prefix
        if sub.endswith(f".{domain}"):
            prefix = sub[: -len(domain) - 1]
        else:
            continue

        # 1. Prefix/suffix with common keywords
        for kw in PERMUTATION_KEYWORDS:
            candidates.add(f"{kw}-{prefix}.{domain}")
            candidates.add(f"{prefix}-{kw}.{domain}")
            candidates.add(f"{kw}{prefix}.{domain}")
            candidates.add(f"{prefix}{kw}.{domain}")

        # 2. Number iteration
        for n in range(1, 21):
            candidates.add(f"{prefix}{n}.{domain}")
            candidates.add(f"{n}{prefix}.{domain}")

        # 3. Leetspeak variations (limit to avoid explosion)
        for variation in apply_leetseak(prefix)[:10]:
            if variation != prefix:
                candidates.add(f"{variation}.{domain}")

        # 4. Hyphenation — try splitting at common points
        # e.g., "devapi" -> "dev-api"
        for kw in PERMUTATION_KEYWORDS[:20]:
            if kw in prefix and len(prefix) > len(kw) + 1:
                idx = prefix.find(kw)
                if idx > 0:
                    candidates.add(f"{prefix[:idx]}-{prefix[idx:]}.{domain}")
                if idx + len(kw) < len(prefix):
                    candidates.add(f"{prefix[:idx + len(kw)]}-{prefix[idx + len(kw):]}.{domain}")

        # 5. Word substitution — swap known component words
        # e.g., "api-v1" -> "api-v2", "api-beta" -> "api-prod"
        common_swaps = {
            "v1": ["v2", "v3", "v4", "v5"],
            "v2": ["v1", "v3"],
            "beta": ["alpha", "prod", "production", "stable", "release"],
            "alpha": ["beta", "prod"],
            "dev": ["prod", "stage", "staging", "live"],
            "stage": ["dev", "prod", "live"],
            "staging": ["dev", "prod", "live"],
            "prod": ["dev", "stage", "staging", "test"],
            "production": ["dev", "staging", "test"],
            "test": ["prod", "dev", "stage"],
            "testing": ["prod", "dev", "stage"],
            "old": ["new", "current"],
            "new": ["old", "current"],
            "api": ["admin", "portal", "app", "web"],
            "admin": ["api", "portal", "dashboard"],
            "web": ["api", "admin", "app", "portal"],
            "app": ["api", "web", "admin", "portal"],
            "secure": ["admin", "portal", "login", "auth"],
            "login": ["auth", "secure", "sso", "oauth"],
        }
        for old_val, new_vals in common_swaps.items():
            if old_val in prefix:
                for new_val in new_vals:
                    candidates.add(f"{prefix.replace(old_val, new_val)}.{domain}")

    # Filter out invalid domains and originals
    valid: set[str] = set()
    for c in candidates:
        if is_valid_domain(c) and c not in subdomains:
            valid.add(c)

    return valid


def deduplicate(items: list[str]) -> list[str]:
    """Deduplicate a list preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item.lower() not in seen:
            seen.add(item.lower())
            result.append(item)
    return result


async def run_permutation_engine(
    known_subdomains: list[str],
    domain: str,
    max_candidates: int = 5000,
) -> PermutationReport:
    """Run the permutation engine and resolve candidates."""
    report = PermutationReport()

    if not known_subdomains:
        return report

    candidates = generate_permutations(known_subdomains, domain)

    # Limit to avoid excessive DNS queries
    if len(candidates) > max_candidates:
        candidates = set(random.sample(list(candidates), max_candidates))

    report.total_generated = len(candidates)

    if not candidates:
        return report

    # Resolve candidates using thread pool
    loop = asyncio.get_running_loop()

    def try_resolve(hostname: str) -> Optional[str]:
        ip = resolve_hostname(hostname, timeout=3.0)
        return hostname if ip else None

    resolved: list[str] = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(try_resolve, c): c for c in candidates}
        for future in as_completed(futures):
            result = future.result()
            if result:
                resolved.append(result)

    report.total_resolved = len(resolved)
    report.new_subdomains = sorted(resolved)
    return report


# ─── Recursive Discovery ─────────────────────────────────────────────────────

async def discover_recursive(
    domain: str,
    initial_subdomains: list[str],
    max_depth: int = 2,
    vt_api_key: Optional[str] = None,
    st_api_key: Optional[str] = None,
) -> dict[str, list[str]]:
    """Recursively run passive enumeration on discovered subdomains.

    At each depth level, newly discovered subdomains are used as seeds
    for further passive enumeration via crt.sh and CertSpotter.
    """
    results: dict[str, list[str]] = {}
    found = set(initial_subdomains)

    for depth in range(1, max_depth + 1):
        if depth == 1:
            # First depth: use initial subdomains as seeds
            seeds = [s for s in found if s.endswith(f".{domain}")]
        else:
            # Deeper depths: use the subdomains found at the PREVIOUS depth
            prev_key = str(depth - 1)
            seeds = results.get(prev_key, [])

        if not seeds:
            break

        # Run passive enumeration on a sample of subdomains at this depth
        # Use crt.sh on each seed to find deeper subdomains
        discovered_at_depth: set[str] = set()
        # Sample up to 10 seeds per depth to stay within rate limits
        sampled_seeds = random.sample(seeds, min(10, len(seeds)))

        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            tasks = []
            for seed in sampled_seeds:
                # Query crt.sh for the seed subdomain
                tasks.append(_query_crtsh_for_parent(seed, domain, client))

            task_results = await asyncio.gather(*tasks, return_exceptions=True)
            for tr in task_results:
                if isinstance(tr, set):
                    discovered_at_depth.update(tr)

        # Filter to only new subdomains
        new_at_depth = {s for s in discovered_at_depth if s not in found}
        found.update(new_at_depth)

        if new_at_depth:
            results[str(depth)] = sorted(new_at_depth)
        else:
            break

    return results


async def _query_crtsh_for_parent(
    parent_domain: str,
    root_domain: str,
    client: httpx.AsyncClient,
) -> set[str]:
    """Query crt.sh for subdomains of a parent domain (like hostname.*.root.com)."""
    subdomains: set[str] = set()
    # Modify the query to search for the specific domain pattern
    # e.g., if we found "api.example.com", search for "*.api.example.com"
    url = f"https://crt.sh/?q=%25.{parent_domain}&output=json"
    try:
        resp = await client.get(url, headers={
            "User-Agent": "ReconProbe/0.4.0 (Security Research)",
            "Accept": "application/json",
        })
        if resp.status_code != 200:
            return subdomains
        entries = resp.json()
        for entry in entries:
            name_value: str = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                # Accept subdomains of our parent domain
                if name.endswith(f".{parent_domain}") and is_valid_domain(name):
                    subdomains.add(name)
    except (httpx.HTTPError, json.JSONDecodeError, KeyError):
        pass
    return subdomains


# ─── Orchestrator ────────────────────────────────────────────────────────────

async def run_advanced_techniques(
    domain: str,
    known_subdomains: list[str],
    enable_zone_transfer: bool = True,
    enable_permutations: bool = True,
    enable_recursive: bool = True,
    recursive_max_depth: int = 2,
    max_permutation_candidates: int = 5000,
    vt_api_key: Optional[str] = None,
    st_api_key: Optional[str] = None,
) -> AdvancedSubdomainReport:
    """Run all advanced subdomain techniques and return a consolidated report."""
    report = AdvancedSubdomainReport()

    # 1. Zone Transfer
    if enable_zone_transfer:
        zt_results = await attempt_zone_transfer(domain)
        report.zone_transfer_results = zt_results

    # 2. Permutation Engine
    if enable_permutations and known_subdomains:
        perm_report = await run_permutation_engine(
            known_subdomains=known_subdomains,
            domain=domain,
            max_candidates=max_permutation_candidates,
        )
        report.permutation_report = perm_report

    # 3. Recursive Discovery
    if enable_recursive and known_subdomains:
        # Collect all subdomain hostnames
        rec_results = await discover_recursive(
            domain=domain,
            initial_subdomains=known_subdomains,
            max_depth=recursive_max_depth,
            vt_api_key=vt_api_key,
            st_api_key=st_api_key,
        )
        report.recursive_results = rec_results

    # Count total new subdomains
    total = 0
    if report.permutation_report:
        total += report.permutation_report.total_resolved
    for depth_results in report.recursive_results.values():
        total += len(depth_results)
    report.total_new_subdomains = total

    return report
