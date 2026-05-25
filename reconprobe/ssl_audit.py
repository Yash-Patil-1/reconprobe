"""SSL/TLS audit module — deep certificate analysis, protocol scanning, and security header checks.

Performs comprehensive SSL/TLS security assessment including:
- Certificate validation (expiry, issuer, SAN, self-signed, wildcard)
- Protocol version support (TLS 1.0, 1.1, 1.2, 1.3)
- Weak cipher suite detection
- Security headers audit (HSTS, CSP, X-Frame-Options, etc.)
"""

from __future__ import annotations

import asyncio
import ssl
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import httpx


# ── Data structures ──────────────────────────────────────────────────────────


@dataclass
class CertInfo:
    """SSL/TLS certificate information."""
    subject: str = ""
    issuer: str = ""
    common_name: str = ""
    san: list[str] = field(default_factory=list)
    valid_from: str = ""
    valid_to: str = ""
    is_expired: bool = False
    will_expire_soon: bool = False  # Within 30 days
    days_remaining: int = 0
    is_self_signed: bool = False
    is_wildcard: bool = False
    serial_number: str = ""
    version: int = 0
    signature_algorithm: str = ""
    error: Optional[str] = None


@dataclass
class ProtocolCheck:
    """TLS protocol version check result."""
    protocol: str
    supported: bool
    error: Optional[str] = None


@dataclass
class CipherCheck:
    """Cipher suite check result."""
    cipher: str
    supported: bool
    is_weak: bool = False
    reason: Optional[str] = None


@dataclass
class SecurityHeaderCheck:
    """Security header presence and value check."""
    header: str
    present: bool = False
    value: str = ""
    recommended: bool = False
    recommendation: str = ""


@dataclass
class SslAuditReport:
    """Complete SSL/TLS audit report for a single host:port."""
    hostname: str = ""
    port: int = 443
    certificate: Optional[CertInfo] = None
    protocols: list[ProtocolCheck] = field(default_factory=list)
    weak_ciphers: list[CipherCheck] = field(default_factory=list)
    security_headers: list[SecurityHeaderCheck] = field(default_factory=list)
    grade: str = ""  # A, B, C, D, F
    total_issues: int = 0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "port": self.port,
            "certificate": {
                "subject": self.certificate.subject if self.certificate else "",
                "issuer": self.certificate.issuer if self.certificate else "",
                "common_name": self.certificate.common_name if self.certificate else "",
                "san": self.certificate.san if self.certificate else [],
                "valid_from": self.certificate.valid_from if self.certificate else "",
                "valid_to": self.certificate.valid_to if self.certificate else "",
                "is_expired": self.certificate.is_expired if self.certificate else False,
                "will_expire_soon": self.certificate.will_expire_soon if self.certificate else False,
                "days_remaining": self.certificate.days_remaining if self.certificate else 0,
                "is_self_signed": self.certificate.is_self_signed if self.certificate else False,
                "is_wildcard": self.certificate.is_wildcard if self.certificate else False,
                "signature_algorithm": self.certificate.signature_algorithm if self.certificate else "",
            } if self.certificate else {},
            "protocols": [
                {"protocol": p.protocol, "supported": p.supported, "error": p.error}
                for p in self.protocols
            ],
            "weak_ciphers": [
                {"cipher": c.cipher, "supported": c.supported, "is_weak": c.is_weak, "reason": c.reason}
                for c in self.weak_ciphers
            ],
            "security_headers": [
                {
                    "header": h.header, "present": h.present, "value": h.value,
                    "recommended": h.recommended, "recommendation": h.recommendation,
                }
                for h in self.security_headers
            ],
            "grade": self.grade,
            "total_issues": self.total_issues,
            "error": self.error,
        }


# ── Security Headers Reference ──────────────────────────────────────────────

SECURITY_HEADERS = [
    SecurityHeaderCheck(
        header="Strict-Transport-Security",
        recommended=True,
        recommendation="Should set max-age >= 31536000 and includeSubDomains",
    ),
    SecurityHeaderCheck(
        header="Content-Security-Policy",
        recommended=True,
        recommendation="Should restrict script sources and prevent XSS",
    ),
    SecurityHeaderCheck(
        header="X-Frame-Options",
        recommended=True,
        recommendation="Should set to DENY or SAMEORIGIN to prevent clickjacking",
    ),
    SecurityHeaderCheck(
        header="X-Content-Type-Options",
        recommended=True,
        recommendation="Should set to 'nosniff' to prevent MIME sniffing",
    ),
    SecurityHeaderCheck(
        header="Referrer-Policy",
        recommended=True,
        recommendation="Should restrict referrer leakage",
    ),
    SecurityHeaderCheck(
        header="Permissions-Policy",
        recommended=True,
        recommendation="Should restrict feature permissions",
    ),
    SecurityHeaderCheck(
        header="X-XSS-Protection",
        recommended=False,
        recommendation="Deprecated — use Content-Security-Policy instead",
    ),
    SecurityHeaderCheck(
        header="Access-Control-Allow-Origin",
        recommended=False,
        recommendation="Check that CORS is not overly permissive (e.g., '*')",
    ),
    SecurityHeaderCheck(
        header="Set-Cookie",
        recommended=False,
        recommendation="Should include HttpOnly, Secure, SameSite attributes",
    ),
]


# ── Certificate Inspection ──────────────────────────────────────────────────


def inspect_certificate(cert_der: Optional[dict], hostname: str) -> Optional[CertInfo]:
    """Inspect SSL certificate details from the peer certificate dict.

    Python's ssl module returns cert information as a dict via getpeercert().
    This function parses that dict to extract useful information.
    """
    if not cert_der:
        return None

    info = CertInfo()

    try:
        # Subject
        subject = cert_der.get("subject", [])
        cn_parts = []
        for part in subject:
            for key, value in part:
                if key == "commonName":
                    info.common_name = value
                cn_parts.append(f"{key}={value}")
        info.subject = ", ".join(cn_parts)

        # Issuer
        issuer = cert_der.get("issuer", [])
        iss_parts = []
        for part in issuer:
            for key, value in part:
                iss_parts.append(f"{key}={value}")
        info.issuer = ", ".join(iss_parts)

        # SAN (Subject Alternative Names)
        info.san = cert_der.get("subjectAltName", [])
        # Extract just the DNS names
        san_names = []
        for san_entry in info.san:
            if isinstance(san_entry, tuple) and len(san_entry) >= 2:
                san_names.append(san_entry[1])
        info.san = san_names

        # Validity dates
        valid_from = cert_der.get("notBefore", "")
        valid_to = cert_der.get("notAfter", "")

        # Parse dates (format: 'May 21 12:00:00 2026 GMT')
        date_format = "%b %d %H:%M:%S %Y %Z"
        try:
            if valid_from:
                from_dt = datetime.strptime(valid_from, date_format)
                info.valid_from = from_dt.isoformat()
            if valid_to:
                to_dt = datetime.strptime(valid_to, date_format)
                info.valid_to = to_dt.isoformat()
                now = datetime.now(timezone.utc)
                info.days_remaining = (to_dt.replace(tzinfo=timezone.utc) - now).days
                info.is_expired = info.days_remaining < 0
                info.will_expire_soon = 0 <= info.days_remaining <= 30
        except (ValueError, TypeError):
            info.valid_from = valid_from
            info.valid_to = valid_to

        # Self-signed check
        if info.subject == info.issuer:
            info.is_self_signed = True

        # Wildcard check
        if info.common_name.startswith("*.") or any(
            name.startswith("*.") for name in info.san
        ):
            info.is_wildcard = True

        # Serial number
        info.serial_number = str(cert_der.get("serialNumber", ""))

        # Version
        info.version = cert_der.get("version", 0)

        # Signature algorithm
        info.signature_algorithm = cert_der.get("signatureAlgorithm", "")

    except Exception as e:
        info.error = str(e)

    return info


async def check_certificate(hostname: str, port: int, timeout: float = 10.0) -> Optional[CertInfo]:
    """Connect to a host and retrieve its SSL certificate."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port, ssl=ctx), timeout=timeout
        )

        cert_der = writer.get_extra_info("peercert")
        if cert_der:
            info = inspect_certificate(cert_der, hostname)
            writer.close()
            return info

        writer.close()
    except (ssl.SSLError, ConnectionRefusedError, OSError, asyncio.TimeoutError) as e:
        return CertInfo(error=str(e))
    except Exception as e:
        return CertInfo(error=str(e))

    return None


# ── Protocol Version Scanning ───────────────────────────────────────────────


def _create_tls_context(tls_version: int) -> ssl.SSLContext:
    """Create an SSLContext locked to a specific TLS version.

    Uses the modern ``minimum_version``/``maximum_version`` API
    instead of deprecated ``PROTOCOL_TLSv1`` constants.
    Suppresses deprecation warnings for TLS 1.0/1.1 checks in Python 3.13+.
    """
    import warnings
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*TLSVersion.*")
            ctx.minimum_version = ssl.TLSVersion(tls_version)
            ctx.maximum_version = ssl.TLSVersion(tls_version)
    except (AttributeError, ValueError):
        pass
    return ctx


async def check_protocol(
    hostname: str,
    port: int,
    protocol_name: str,
    tls_version: int,
    timeout: float = 5.0,
) -> ProtocolCheck:
    """Check if a specific TLS protocol version is supported."""
    try:
        ctx = _create_tls_context(tls_version)

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port, ssl=ctx), timeout=timeout
        )
        writer.close()
        return ProtocolCheck(protocol=protocol_name, supported=True)
    except ssl.SSLError:
        return ProtocolCheck(protocol=protocol_name, supported=False)
    except (ConnectionRefusedError, OSError, asyncio.TimeoutError) as e:
        return ProtocolCheck(protocol=protocol_name, supported=False, error=str(e))
    except Exception as e:
        return ProtocolCheck(protocol=protocol_name, supported=False, error=str(e))


# ⚠️  SSLv2 and SSLv3 are intentionally omitted — they have been deprecated
#     and are no longer supported by Python's ssl module.
#     TLS 1.0 and 1.1 constants are deprecated in Python 3.13+ but
#     retained here for security auditing — warnings are suppressed at runtime.
PROTOCOLS_TO_CHECK = [
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
]

# TLS 1.3 is checked separately via the PROTOCOL_TLS context
# which negotiates the highest available version


async def check_tls_13(hostname: str, port: int, timeout: float = 5.0) -> ProtocolCheck:
    """Check TLS 1.3 support using a high-level SSL context."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Try to set maximum version to TLS 1.3 if available
        if hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv13"):
            ctx.maximum_version = ssl.TLSVersion.TLSv13

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port, ssl=ctx), timeout=timeout
        )
        # Check what version was negotiated
        negotiated_version = writer.get_extra_info("ssl_object").version()
        writer.close()
        supported = negotiated_version == "TLSv1.3"
        return ProtocolCheck(protocol="TLS 1.3", supported=supported)
    except ssl.SSLError:
        return ProtocolCheck(protocol="TLS 1.3", supported=False)
    except (ConnectionRefusedError, OSError, asyncio.TimeoutError) as e:
        return ProtocolCheck(protocol="TLS 1.3", supported=False, error=str(e))
    except Exception as e:
        return ProtocolCheck(protocol="TLS 1.3", supported=False, error=str(e))


async def scan_protocols(hostname: str, port: int) -> list[ProtocolCheck]:
    """Scan which TLS protocol versions a server supports."""
    results: list[ProtocolCheck] = []
    tasks = []

    for name, version_const in PROTOCOLS_TO_CHECK:
        tasks.append(check_protocol(hostname, port, name, version_const))

    # TLS 1.3 check
    tasks.append(check_tls_13(hostname, port))

    protocol_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in protocol_results:
        if isinstance(result, ProtocolCheck):
            results.append(result)
        else:
            results.append(ProtocolCheck(protocol="unknown", supported=False, error=str(result)))

    # Sort: TLS 1.0 -> 1.1 -> 1.2 -> 1.3
    proto_order = {"TLS 1.0": 0, "TLS 1.1": 1, "TLS 1.2": 2, "TLS 1.3": 3}
    results.sort(key=lambda r: proto_order.get(r.protocol, 99))

    return results


# ── Weak Cipher Detection ───────────────────────────────────────────────────


# Reference list of known weak/obsolete ciphers
WEAK_CIPHERS = {
    "RC4": "RC4 is broken and should not be used",
    "DES": "DES is obsolete and easily brute-forced",
    "3DES": "Triple DES is deprecated and vulnerable to Sweet32 attack",
    "EXPORT": "EXPORT grade ciphers are weak and should not be used",
    "NULL": "NULL ciphers provide no encryption",
    "ANON": "Anonymous key exchange provides no authentication",
    "MD5": "MD5 is broken and should not be used for signing",
    "IDEA": "IDEA cipher is outdated",
    "SEED": "SEED cipher is rarely used and not recommended",
    "CBC": "CBC mode ciphers may be vulnerable to padding oracle attacks (POODLE, Lucky13)",
    "DSS": "DSS signatures use 1024-bit keys which are considered weak",
}


async def check_weak_ciphers(hostname: str, port: int) -> list[CipherCheck]:
    """Identify weak/obsolete cipher suites supported by the server.

    Uses OpenSSL cipher names and attempted connections to detect weak ciphers.
    """
    results: list[CipherCheck] = []
    tested: set[str] = set()

    for weakness_indicator, reason in WEAK_CIPHERS.items():
        cipher_name = weakness_indicator
        if cipher_name in tested:
            continue
        tested.add(cipher_name)

        # Try connecting with a cipher list focused on this weakness
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Set cipher list to include the weak cipher
            try:
                ctx.set_ciphers(weakness_indicator)
            except ssl.SSLError:
                # Cipher not available in this OpenSSL build
                continue

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=ctx), timeout=5.0
            )
            negotiated_cipher = writer.get_extra_info("cipher")
            writer.close()

            if negotiated_cipher:
                cipher_name_full = negotiated_cipher[0] if isinstance(negotiated_cipher, tuple) else str(negotiated_cipher)
                results.append(CipherCheck(
                    cipher=cipher_name_full,
                    supported=True,
                    is_weak=True,
                    reason=reason,
                ))
        except (ssl.SSLError, ConnectionRefusedError, OSError, asyncio.TimeoutError):
            # Cipher not supported — good
            pass
        except Exception:
            pass

    return results


# ── Security Headers Audit ──────────────────────────────────────────────────


async def check_security_headers(
    hostname: str,
    port: int,
    timeout: float = 10.0,
    proxy_url: Optional[str] = None,
) -> list[SecurityHeaderCheck]:
    """Fetch the page and check security headers.

    Returns a list of SecurityHeaderCheck objects indicating which security
    headers are present and their values.
    """
    results: list[SecurityHeaderCheck] = [
        SecurityHeaderCheck(
            header=h.header,
            recommended=h.recommended,
            recommendation=h.recommendation,
        )
        for h in SECURITY_HEADERS
    ]

    url = f"https://{hostname}:{port}/" if port != 443 else f"https://{hostname}/"

    client_kwargs: dict = {
        "verify": False,
        "timeout": httpx.Timeout(timeout),
        "follow_redirects": True,
    }
    if proxy_url:
        client_kwargs["proxies"] = proxy_url

    try:
        async with httpx.AsyncClient(**client_kwargs) as client:
            resp = await client.get(url, headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                              "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            })

            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            for check in results:
                header_key = check.header.lower()
                if header_key in headers_lower:
                    check.present = True
                    check.value = headers_lower[header_key]

            # Specific checks
            hsts_check = next((r for r in results if r.header == "Strict-Transport-Security"), None)
            if hsts_check and hsts_check.present:
                if "max-age=" in hsts_check.value:
                    import re
                    age_match = re.search(r"max-age=(\d+)", hsts_check.value)
                    if age_match:
                        max_age = int(age_match.group(1))
                        if max_age < 31536000:
                            hsts_check.recommendation = (
                                f"HSTS max-age={max_age} is too low. Recommend >= 31536000"
                            )

            xfo_check = next((r for r in results if r.header == "X-Frame-Options"), None)
            if xfo_check and xfo_check.present:
                val = xfo_check.value.upper()
                if val not in ("DENY", "SAMEORIGIN"):
                    xfo_check.recommendation = f"X-Frame-Options: {val} is not secure. Use DENY or SAMEORIGIN"

            csp_check = next((r for r in results if r.header == "Content-Security-Policy"), None)
            if csp_check and csp_check.present:
                if "unsafe-inline" in csp_check.value.lower() or "unsafe-eval" in csp_check.value.lower():
                    csp_check.recommendation = (
                        "CSP allows unsafe-inline or unsafe-eval, reducing XSS protection"
                    )

            cors_check = next((r for r in results if r.header == "Access-Control-Allow-Origin"), None)
            if cors_check and cors_check.present:
                if cors_check.value.strip() == "*":
                    cors_check.recommendation = "CORS allows all origins ('*'), which can lead to data exposure"

    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError):
        pass
    except Exception:
        pass

    return results


# ── Grading Logic ──────────────────────────────────────────────────────────


def calculate_grade(report: SslAuditReport) -> str:
    """Calculate an SSL/TLS security grade (A-F) based on findings."""
    issues = 0

    # Certificate issues (weight: high)
    if report.certificate:
        if report.certificate.is_expired:
            issues += 10
        if report.certificate.will_expire_soon:
            issues += 5
        if report.certificate.is_self_signed:
            issues += 8
        if report.certificate.is_wildcard:
            issues += 3

    # Protocol issues (weight: medium-high)
    for proto in report.protocols:
        if proto.protocol in ("TLS 1.0", "TLS 1.1") and proto.supported:
            issues += 6
        if proto.protocol == "TLS 1.3" and not proto.supported:
            issues += 2

    # Weak ciphers (weight: high)
    issues += len(report.weak_ciphers) * 5

    # Missing security headers (weight: low-medium)
    missing_recommended = sum(
        1 for h in report.security_headers if h.recommended and not h.present
    )
    issues += missing_recommended * 2

    report.total_issues = issues

    if issues <= 3:
        return "A"
    elif issues <= 8:
        return "B"
    elif issues <= 15:
        return "C"
    elif issues <= 25:
        return "D"
    else:
        return "F"


# ── Main Orchestrator ───────────────────────────────────────────────────────


async def audit_ssl(
    hostname: str,
    port: int = 443,
    check_protos: bool = True,
    check_ciphers: bool = True,
    check_headers: bool = True,
    proxy_url: Optional[str] = None,
) -> SslAuditReport:
    """Run a full SSL/TLS audit against a host:port.

    Args:
        hostname: Target hostname.
        port: Target port (default 443).
        check_protos: Whether to check TLS protocol versions.
        check_ciphers: Whether to check for weak ciphers.
        check_headers: Whether to check security headers.
        proxy_url: Optional proxy URL for HTTP header checks.

    Returns:
        SslAuditReport with all findings and a security grade.
    """
    report = SslAuditReport(hostname=hostname, port=port)

    try:
        # 1. Certificate inspection
        cert_info = await check_certificate(hostname, port)
        report.certificate = cert_info

        # 2. Protocol version scanning
        if check_protos:
            protos = await scan_protocols(hostname, port)
            report.protocols = protos

        # 3. Weak cipher detection
        if check_ciphers:
            weak_ciphers = await check_weak_ciphers(hostname, port)
            report.weak_ciphers = weak_ciphers

        # 4. Security headers audit
        if check_headers:
            headers = await check_security_headers(hostname, port, proxy_url=proxy_url)
            report.security_headers = headers

        # 5. Calculate grade
        report.grade = calculate_grade(report)

    except Exception as e:
        report.error = str(e)

    return report


async def audit_ssl_hosts(
    hosts: list[tuple[str, int]],
    check_protos: bool = True,
    check_ciphers: bool = True,
    check_headers: bool = True,
    proxy_url: Optional[str] = None,
    max_concurrent: int = 5,
) -> dict[str, SslAuditReport]:
    """Audit SSL/TLS for multiple hosts in parallel.

    Args:
        hosts: List of (hostname, port) tuples.
        check_protos, check_ciphers, check_headers: Audit options.
        proxy_url: Optional proxy URL.
        max_concurrent: Maximum concurrent audits.

    Returns:
        Dict of "{hostname}:{port}" -> SslAuditReport.
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    async def audit_one(hostname: str, port: int) -> tuple[str, SslAuditReport]:
        async with semaphore:
            report = await audit_ssl(
                hostname, port,
                check_protos=check_protos,
                check_ciphers=check_ciphers,
                check_headers=check_headers,
                proxy_url=proxy_url,
            )
            return f"{hostname}:{port}", report

    tasks = [audit_one(h, p) for h, p in hosts]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    reports: dict[str, SslAuditReport] = {}
    for result in results:
        if isinstance(result, tuple):
            key, report = result
            reports[key] = report

    return reports
