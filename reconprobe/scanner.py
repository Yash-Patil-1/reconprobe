"""Port scanning module.

Multi-threaded TCP connect scan with service fingerprinting via banner grabbing.
Supports both internal socket-based scanning and external masscan integration.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from reconprobe.utils import banner_grab, COMMON_PORTS
from reconprobe.scanner_advanced import (
    run_advanced_port_scan,
    TOP_1000_PORTS,
)


@dataclass
class PortResult:
    """Result from a single port scan."""
    port: int
    state: str  # "open", "filtered", "closed"
    service: str = ""
    banner: Optional[str] = None
    service_version: Optional[dict] = None  # from advanced version detection
    os_fingerprint: Optional[dict] = None   # from advanced OS fingerprinting

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    def to_dict(self) -> dict:
        d: dict = {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
        }
        if self.service_version:
            d["service_version"] = self.service_version
        if self.os_fingerprint:
            d["os_fingerprint"] = self.os_fingerprint
        return d


@dataclass
class HostScanReport:
    """Scan report for a single host."""
    hostname: str
    ip_address: str
    ports: list[PortResult] = field(default_factory=list)
    open_ports: int = 0

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "open_ports": self.open_ports,
            "ports": [p.to_dict() for p in self.ports],
        }


def scan_port(
    host: str,
    port: int,
    timeout: float = 2.0,
    grab_banner: bool = True,
) -> PortResult:
    """Scan a single TCP port on the given host."""
    service = COMMON_PORTS.get(port, "Unknown")
    try:
        with socket.create_connection((host, port), timeout=timeout):
            banner = None
            if grab_banner:
                banner = banner_grab(host, port, timeout=timeout)
            return PortResult(port=port, state="open", service=service, banner=banner)
    except (socket.timeout, OSError):
        return PortResult(port=port, state="closed", service=service)


def scan_host(
    hostname: str,
    ip_address: str,
    ports: Optional[list[int]] = None,
    max_workers: int = 100,
    timeout: float = 2.0,
    grab_banner: bool = True,
) -> HostScanReport:
    """Scan all specified ports on the given host using a thread pool."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    report = HostScanReport(hostname=hostname, ip_address=ip_address)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, ip_address, port, timeout, grab_banner): port
            for port in ports
        }
        for future in as_completed(futures):
            result = future.result()
            report.ports.append(result)
            if result.is_open:
                report.open_ports += 1

    # Sort ports by port number for consistent output
    report.ports.sort(key=lambda p: p.port)
    return report


def scan_host_masscan(
    hostname: str,
    ip_address: str,
    ports: Optional[list[int]] = None,
    rate: int = 1000,
    timeout: float = 30.0,
    grab_banner: bool = True,
) -> HostScanReport:
    """Scan a host using masscan for high-speed port detection.

    Falls back to internal socket scan if masscan is unavailable or fails.
    """
    report = HostScanReport(hostname=hostname, ip_address=ip_address)

    if ports is None:
        ports = list(COMMON_PORTS.keys())

    # Build port string for masscan
    port_str = ",".join(str(p) for p in ports)

    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            output_path = tmp.name

        cmd = [
            "masscan",
            ip_address,
            "-p", port_str,
            "--rate", str(rate),
            "-oJ", output_path,
            "--wait", "0",
        ]

        subprocess.run(
            cmd,
            timeout=timeout,
            capture_output=True,
            text=True,
        )

        # Parse masscan JSON output (one JSON object per line)
        open_ports: list[int] = []
        if os.path.isfile(output_path) and os.path.getsize(output_path) > 0:
            with open(output_path) as f:
                content = f.read().strip()
                # Masscan wraps output in brackets
                if content.startswith("[") and content.endswith("]"):
                    try:
                        entries = json.loads(content)
                        for entry in entries:
                            port = entry.get("ports", [{}])[0].get("port")
                            if port:
                                open_ports.append(int(port))
                    except (json.JSONDecodeError, IndexError, KeyError):
                        pass
                else:
                    # Fallback: line-by-line JSON
                    for line in content.split("\n"):
                        line = line.strip().rstrip(",")
                        if line.startswith("{"):
                            try:
                                entry = json.loads(line)
                                port = entry.get("ports", [{}])[0].get("port")
                                if port:
                                    open_ports.append(int(port))
                            except (json.JSONDecodeError, IndexError, KeyError):
                                pass

        # Clean up temp file
        try:
            os.unlink(output_path)
        except OSError:
            pass

        # Build port results from masscan findings
        for port in sorted(open_ports):
            service = COMMON_PORTS.get(port, "Unknown")
            banner = None
            if grab_banner:
                banner = banner_grab(ip_address, port)
            report.ports.append(
                PortResult(port=port, state="open", service=service, banner=banner)
            )
            report.open_ports += 1

        # For ports not found by masscan, mark them as closed
        scanned_ports = set(open_ports)
        for port in ports:
            if port not in scanned_ports:
                service = COMMON_PORTS.get(port, "Unknown")
                report.ports.append(
                    PortResult(port=port, state="closed", service=service)
                )

    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        # Masscan unavailable or failed — fall back to internal scanner
        import warnings
        warnings.warn(f"masscan scan failed ({e}), falling back to internal scanner")
        report = scan_host(hostname, ip_address, ports, grab_banner=grab_banner)

    report.ports.sort(key=lambda p: p.port)
    return report


def scan_host_advanced(
    hostname: str,
    ip_address: str,
    ports: Optional[list[int]] = None,
    max_workers: int = 100,
    timeout: float = 2.0,
    grab_banner: bool = True,
    enable_version_detection: bool = True,
    enable_os_fingerprinting: bool = False,
) -> HostScanReport:
    """Scan a host and perform advanced service version detection and OS fingerprinting.

    Runs the standard port scan first, then for each open port performs
    service-specific version probing and optional OS fingerprinting.
    """
    report = scan_host(
        hostname=hostname,
        ip_address=ip_address,
        ports=ports,
        max_workers=max_workers,
        timeout=timeout,
        grab_banner=grab_banner,
    )

    if not (enable_version_detection or enable_os_fingerprinting):
        return report

    # Run advanced probing on each open port (sync — no asyncio needed)
    open_ports = [p for p in report.ports if p.is_open]

    def _probe_port(port_result):
        try:
            advanced = run_advanced_port_scan(
                host=ip_address,
                port=port_result.port,
                timeout=max(timeout, 5.0),
                enable_version_detection=enable_version_detection,
                enable_os_fingerprinting=enable_os_fingerprinting,
            )
            if advanced.service_version:
                port_result.service_version = {
                    "service_name": advanced.service_version.service_name,
                    "version": advanced.service_version.version,
                    "product": advanced.service_version.product,
                    "extra_info": advanced.service_version.extra_info,
                }
                if advanced.service_version.product:
                    port_result.service = advanced.service_version.product
            if advanced.os_fingerprint and advanced.os_fingerprint.guessed_os != "Unknown":
                port_result.os_fingerprint = {
                    "guessed_os": advanced.os_fingerprint.guessed_os,
                    "confidence": advanced.os_fingerprint.confidence,
                    "ttl": advanced.os_fingerprint.ttl,
                    "tcp_window": advanced.os_fingerprint.tcp_window,
                }
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=min(10, len(open_ports) or 1)) as executor:
        list(executor.map(_probe_port, open_ports))

    return report


def get_scan_ports(
    ports: Optional[list[int]] = None,
    top_1000: bool = False,
) -> list[int]:
    """Resolve the list of ports to scan.

    If `ports` is provided, use that.
    If `top_1000` is True, use the top 1000 ports.
    Otherwise, use COMMON_PORTS keys.
    """
    if ports is not None:
        return ports
    if top_1000:
        return TOP_1000_PORTS
    return list(COMMON_PORTS.keys())



