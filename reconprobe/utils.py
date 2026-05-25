"""Utility functions for ReconProbe."""

import re
import socket
from typing import Optional

DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def is_valid_domain(domain: str) -> bool:
    """Check if the given string is a valid domain name."""
    return bool(DOMAIN_RE.match(domain))


def extract_domains(text: str) -> set[str]:
    """Extract unique domain-like strings from arbitrary text."""
    pattern = re.compile(
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
    )
    return set(pattern.findall(text))


def resolve_hostname(hostname: str, timeout: float = 3.0) -> Optional[str]:
    """Resolve a hostname to an IP address. Returns None on failure."""
    try:
        return socket.getaddrinfo(hostname, 80, type=socket.SOCK_STREAM)[0][4][0]
    except (socket.gaierror, OSError):
        return None


def banner_grab(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """Attempt to grab a service banner from the given host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            # For HTTP services, send a minimal probe
            if port in (80, 443, 8080, 8443):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            else:
                # Try a generic probe for other services
                sock.sendall(b"\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            return banner if banner else None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "IKE",
    514: "Syslog",
    587: "SMTP Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle DB",
    2049: "NFS",
    2375: "Docker",
    2376: "Docker TLS",
    3128: "Squid Proxy",
    3306: "MySQL",
    3389: "RDP",
    3690: "SVN",
    4444: "Metasploit Default",
    5000: "Flask/Upnp",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6379: "Redis",
    6443: "Kubernetes API",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt2",
    9000: "PHP-FPM/SonarQube",
    9090: "Cockpit/Prometheus",
    9200: "Elasticsearch",
    9392: "OpenVAS",
    10000: "Webmin",
    11211: "Memcached",
    27017: "MongoDB",
    32400: "Plex",
}
