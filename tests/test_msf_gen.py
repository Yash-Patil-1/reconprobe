"""Tests for the Metasploit resource script generator (reconprobe.msf_gen)."""

from __future__ import annotations


from reconprobe.msf_gen import (
    MsfModule,
    MsfScript,
    _build_exploit_module_command,
    _build_auxiliary_module_command,
    generate_port_scan_modules,
    generate_exploit_modules,
    _map_exploit_to_msf,
    generate_msf_script,
    generate_msf_script_full,
)


# ── Data structure tests ────────────────────────────────────────────────────


class TestDataStructures:
    def test_msf_module_defaults(self):
        m = MsfModule(module_path="exploit/test")
        assert m.options == {}
        assert m.description is None
        assert m.run is True

    def test_msf_module_with_options(self):
        m = MsfModule(module_path="exploit/test", options={"RHOSTS": "10.0.0.1", "RPORT": "80"})
        assert m.options["RHOSTS"] == "10.0.0.1"
        assert m.options["RPORT"] == "80"

    def test_msf_script_empty(self):
        s = MsfScript(path="script.rc")
        assert s.module_count == 0
        assert s.auxiliary_count == 0
        assert s.exploit_count == 0
        assert s.content == ""

    def test_msf_script_counts(self):
        modules = [
            MsfModule(module_path="auxiliary/scanner/smb/smb_enumusers"),
            MsfModule(module_path="exploit/windows/smb/ms17_010_eternalblue"),
            MsfModule(module_path="auxiliary/scanner/ssh/ssh_version"),
        ]
        s = MsfScript(path="t.rc", modules=modules, content="content")
        assert s.module_count == 3
        assert s.auxiliary_count == 2
        assert s.exploit_count == 1


# ── Command building tests ──────────────────────────────────────────────────


class TestBuildExploitModuleCommand:
    def test_basic_module(self):
        m = MsfModule(module_path="exploit/test", options={"RHOSTS": "10.0.0.1"}, description="Test")
        cmd = _build_exploit_module_command(m)
        assert "use exploit/test" in cmd
        assert "set RHOSTS 10.0.0.1" in cmd
        assert "# Test" in cmd
        assert "run -j" in cmd

    def test_no_run(self):
        m = MsfModule(module_path="auxiliary/test", run=False)
        cmd = _build_exploit_module_command(m)
        assert "run -j" not in cmd

    def test_multiple_options(self):
        m = MsfModule(module_path="exploit/test", options={"RHOSTS": "x", "RPORT": "8080", "SSL": "true"})
        cmd = _build_exploit_module_command(m)
        assert "set RHOSTS x" in cmd
        assert "set RPORT 8080" in cmd
        assert "set SSL true" in cmd

    def test_auxiliary_builder(self):
        m = MsfModule(module_path="auxiliary/scanner/ssh/ssh_version", options={"RHOSTS": "10.0.0.1"})
        cmd = _build_auxiliary_module_command(m)
        assert "use auxiliary/scanner/ssh/ssh_version" in cmd

    def test_indent(self):
        m = MsfModule(module_path="exploit/test", options={"RHOSTS": "x"})
        cmd = _build_exploit_module_command(m, indent=4)
        for line in cmd.rstrip("\n").split("\n"):
            stripped = line.strip()
            if stripped:  # non-empty line should be indented
                assert line.startswith("    "), f"Line missing indent: {repr(line)}"


# ── Port scan module generation tests ───────────────────────────────────────


class TestGeneratePortScanModules:
    def test_empty_ports(self):
        modules = generate_port_scan_modules([], "test.com")
        assert modules == []

    def test_smb_ports_generate_modules(self):
        open_ports = [
            {"port": 445, "protocol": "tcp", "service": "smb", "version": ""},
        ]
        modules = generate_port_scan_modules(open_ports, "test.com")
        assert len(modules) > 0
        paths = {m.module_path for m in modules}
        assert "auxiliary/scanner/smb/smb_enumusers" in paths
        assert "auxiliary/scanner/smb/smb_enumshares" in paths
        assert "auxiliary/scanner/smb/smb_version" in paths

    def test_ssh_ports_generate_modules(self):
        open_ports = [
            {"port": 22, "protocol": "tcp", "service": "ssh", "version": ""},
        ]
        modules = generate_port_scan_modules(open_ports, "test.com")
        paths = {m.module_path for m in modules}
        assert "auxiliary/scanner/ssh/ssh_version" in paths
        assert "auxiliary/scanner/ssh/ssh_enumusers" in paths

    def test_http_ports_generate_modules(self):
        open_ports = [
            {"port": 80, "protocol": "tcp", "service": "http", "version": ""},
        ]
        modules = generate_port_scan_modules(open_ports, "test.com")
        paths = {m.module_path for m in modules}
        assert "auxiliary/scanner/http/http_version" in paths
        assert "auxiliary/scanner/http/robots_txt" in paths

    def test_mysql_ports_generate_modules(self):
        open_ports = [
            {"port": 3306, "protocol": "tcp", "service": "mysql", "version": ""},
        ]
        modules = generate_port_scan_modules(open_ports, "test.com")
        paths = {m.module_path for m in modules}
        assert "auxiliary/scanner/mysql/mysql_version" in paths
        assert "auxiliary/scanner/mysql/mysql_enum" in paths
        assert "auxiliary/scanner/mysql/mysql_schemadump" in paths

    def test_postgres_ports_generate_modules(self):
        open_ports = [
            {"port": 5432, "protocol": "tcp", "service": "postgresql", "version": ""},
        ]
        modules = generate_port_scan_modules(open_ports, "test.com")
        paths = {m.module_path for m in modules}
        assert "auxiliary/scanner/postgres/postgres_version" in paths

    def test_ftp_ports_generate_modules(self):
        open_ports = [
            {"port": 21, "protocol": "tcp", "service": "ftp", "version": ""},
        ]
        modules = generate_port_scan_modules(open_ports, "test.com")
        paths = {m.module_path for m in modules}
        assert "auxiliary/scanner/ftp/ftp_version" in paths
        assert "auxiliary/scanner/ftp/anonymous" in paths

    def test_rdp_ports_generate_modules(self):
        open_ports = [
            {"port": 3389, "protocol": "tcp", "service": "rdp", "version": ""},
        ]
        modules = generate_port_scan_modules(open_ports, "test.com")
        paths = {m.module_path for m in modules}
        assert "auxiliary/scanner/rdp/rdp_scanner" in paths

    def test_ms17_010_check(self):
        """SMB ports should also get the MS17-010 check module."""
        open_ports = [
            {"port": 445, "protocol": "tcp", "service": "smb"},
        ]
        modules = generate_port_scan_modules(open_ports, "test.com")
        paths = {m.module_path for m in modules}
        assert "auxiliary/scanner/smb/smb_ms17_010" in paths

    def test_no_duplicate_services(self):
        """Same service on multiple ports should not duplicate modules."""
        open_ports = [
            {"port": 139, "protocol": "tcp", "service": "smb"},
            {"port": 445, "protocol": "tcp", "service": "smb"},
        ]
        modules = generate_port_scan_modules(open_ports, "test.com")
        paths = [m.module_path for m in modules]
        # Each module should appear only once
        assert len(paths) == len(set(paths))

    def test_https_ssl_flag(self):
        """HTTPS ports should have SSL=true option."""
        open_ports = [
            {"port": 443, "protocol": "tcp", "service": "http"},
        ]
        modules = generate_port_scan_modules(open_ports, "test.com")
        http_version = next(m for m in modules if "http_version" in m.module_path)
        assert http_version.options.get("SSL") == "true"

    def test_http_no_ssl(self):
        """HTTP ports should have SSL=false."""
        open_ports = [
            {"port": 80, "protocol": "tcp", "service": "http"},
        ]
        modules = generate_port_scan_modules(open_ports, "test.com")
        http_version = next(m for m in modules if "http_version" in m.module_path)
        assert http_version.options.get("SSL") == "false"

    def test_lhost_passed_through(self):
        open_ports = [
            {"port": 22, "protocol": "tcp", "service": "ssh"},
        ]
        modules = generate_port_scan_modules(open_ports, "test.com", lhost="10.0.0.1")
        for m in modules:
            assert m.options.get("RHOSTS") == "test.com"


# ── Exploit module mapping tests ────────────────────────────────────────────


class TestMapExploitToMsf:
    def test_edb_vsftpd(self):
        m = _map_exploit_to_msf("EDB-17491", "ftp", "CVE-2011-2523")
        assert m is not None
        assert "vsftpd_234_backdoor" in m.module_path
        assert m.description is not None

    def test_edb_proftpd(self):
        m = _map_exploit_to_msf("EDB-49794", "ftp", "CVE-2015-3306")
        assert m is not None
        assert "proftpd" in m.module_path

    def test_edb_apache_2_4_49(self):
        m = _map_exploit_to_msf("EDB-50383", "apache", "CVE-2021-41773")
        assert m is not None
        assert "apache" in m.module_path

    def test_edb_bluekeep(self):
        m = _map_exploit_to_msf("EDB-49707", "rdp", "CVE-2019-0708")
        assert m is not None
        assert "bluekeep" in m.module_path or "rdp" in m.module_path

    def test_cve_based_mapping(self):
        m = _map_exploit_to_msf("EDB-UNKNOWN", "http", "CVE-2021-44228")
        assert m is not None
        assert "log4shell" in m.module_path

    def test_service_based_fallback(self):
        m = _map_exploit_to_msf("EDB-UNKNOWN", "ftp", "")
        assert m is not None
        assert "ftp" in m.module_path

    def test_unknown_returns_none(self):
        m = _map_exploit_to_msf("EDB-999999", "unknown", "")
        assert m is None


class TestGenerateExploitModules:
    def test_empty_suggestions(self):
        modules = generate_exploit_modules([], "test.com")
        assert modules == []

    def test_dict_suggestions(self):
        suggestions = [
            {"edb_id": "EDB-17491", "service": "ftp", "cve_id": "CVE-2011-2523", "port": 21},
        ]
        modules = generate_exploit_modules(suggestions, "test.com", lhost="10.0.0.1", lport=4444)
        assert len(modules) >= 1
        module = modules[0]
        assert module.options.get("RHOSTS") == "test.com"
        assert module.options.get("RPORT") == "21"

    def test_object_suggestions(self):
        """Test with ExploitSuggestion-like objects."""
        suggestion = type("MockSuggestion", (), {
            "edb_id": "EDB-17491", "service": "ftp", "cve_id": "CVE-2011-2523", "port": 21
        })()
        modules = generate_exploit_modules([suggestion], "test.com")
        assert len(modules) >= 1

    def test_no_duplicate_modules(self):
        """Same exploit should not appear twice."""
        suggestions = [
            {"edb_id": "EDB-17491", "service": "ftp", "cve_id": "CVE-2011-2523"},
            {"edb_id": "EDB-17491", "service": "ftp", "cve_id": "CVE-2011-2523"},
        ]
        modules = generate_exploit_modules(suggestions, "test.com")
        assert len(modules) == 1


# ── Full script generation tests ────────────────────────────────────────────


class TestGenerateMsfScript:
    def test_basic_script_structure(self):
        open_ports = [
            {"port": 22, "protocol": "tcp", "service": "ssh"},
            {"port": 80, "protocol": "tcp", "service": "http"},
        ]
        script = generate_msf_script("test.com", open_ports)
        content = script.content

        assert "Metasploit Resource Script" in content
        assert "# Generated by ReconProbe" in content
        assert "test.com" in content
        assert "setg LHOST 127.0.0.1" in content
        assert "setg LPORT 4444" in content
        assert "setg VERBOSE true" in content
        assert "use auxiliary/scanner/ssh/ssh_version" in content
        assert "use auxiliary/scanner/http/http_version" in content
        assert "# EOF" in content

    def test_with_exploit_suggestions(self):
        open_ports = [
            {"port": 21, "protocol": "tcp", "service": "ftp"},
        ]
        suggestions = [
            {"edb_id": "EDB-17491", "service": "ftp", "cve_id": "CVE-2011-2523", "port": 21},
        ]
        script = generate_msf_script("test.com", open_ports, exploit_suggestions=suggestions)
        content = script.content

        assert "use exploit/multi/handler" in content
        assert "set PAYLOAD generic/shell_reverse_tcp" in content

    def test_no_exploit_suggestions(self):
        open_ports = [{"port": 22, "protocol": "tcp", "service": "ssh"}]
        script = generate_msf_script("test.com", open_ports, exploit_suggestions=None)
        content = script.content

        assert "# Start a generic handler" not in content  # No handler without exploits

    def test_with_post_exploitation(self):
        open_ports = [{"port": 22, "protocol": "tcp", "service": "ssh"}]
        script = generate_msf_script("test.com", open_ports, include_post=True)
        content = script.content

        assert "POST-EXPLOITATION" in content or "post/" in content

    def test_without_post_exploitation(self):
        open_ports = [{"port": 22, "protocol": "tcp", "service": "ssh"}]
        script = generate_msf_script("test.com", open_ports, include_post=False)
        content = script.content

        assert "POST-EXPLOITATION" not in content

    def test_module_counts(self):
        open_ports = [
            {"port": 22, "protocol": "tcp", "service": "ssh"},
            {"port": 445, "protocol": "tcp", "service": "smb"},
        ]
        script = generate_msf_script("test.com", open_ports)
        assert script.module_count > 0
        assert script.auxiliary_count > 0
        assert script.exploit_count == 0  # No exploit suggestions

    def test_custom_lhost_lport(self):
        open_ports = [{"port": 22, "protocol": "tcp", "service": "ssh"}]
        script = generate_msf_script("test.com", open_ports, lhost="10.0.0.5", lport=8888)
        content = script.content

        assert "setg LHOST 10.0.0.5" in content
        assert "setg LPORT 8888" in content

    def test_lhost_in_exploit_modules(self):
        open_ports = [{"port": 445, "protocol": "tcp", "service": "smb"}]
        suggestions = [{"edb_id": "EDB-49318", "service": "smb", "cve_id": "CVE-2020-1472"}]
        script = generate_msf_script("test.com", open_ports, exploit_suggestions=suggestions, lhost="10.0.0.1", lport=5555)
        content = script.content

        # The handler should use our custom LHOST/LPORT
        assert "setg LHOST 10.0.0.1" in content
        assert "setg LPORT 5555" in content


# ── Full scan integration tests ─────────────────────────────────────────────


class TestGenerateMsfScriptFull:
    def test_from_scan_results(self):
        scan_results = {
            "scanner_data": {
                "host1": {
                    "ports": [
                        {"port": 22, "protocol": "tcp", "service": "ssh"},
                        {"port": 80, "protocol": "tcp", "service": "http"},
                    ]
                }
            },
        }
        script = generate_msf_script_full("test.com", scan_results, lhost="10.0.0.1", lport=4444)
        assert script.module_count > 0
        assert "test.com" in script.content
        assert "use auxiliary/scanner/ssh/ssh_version" in script.content

    def test_empty_scan_results(self):
        script = generate_msf_script_full("test.com", {})
        assert script.auxiliary_count == 0
        assert script.exploit_count == 0
        assert script.content is not None  # Should still have header/global options

    def test_with_exploit_data(self):
        scan_results = {
            "scanner_data": {
                "host1": {
                    "ports": [
                        {"port": 21, "protocol": "tcp", "service": "ftp"},
                    ]
                }
            },
            "exploit_data": {
                "suggestions": [
                    {"edb_id": "EDB-17491", "service": "ftp", "cve_id": "CVE-2011-2523", "port": 21},
                ]
            },
        }
        script = generate_msf_script_full("test.com", scan_results)
        assert script.exploit_count >= 1
        assert "vsftpd" in script.content

    def test_handles_object_ports(self):
        """Test with object-like port structures from scan data."""
        port_obj = type("MockPort", (), {"port": 22, "protocol": "tcp", "service": "ssh", "version": None})()
        scan_results = {
            "scanner_data": {
                "host1": {
                    "ports": [port_obj]
                }
            },
        }
        script = generate_msf_script_full("test.com", scan_results)
        assert script.module_count > 0

    def test_exploit_data_alternate_key(self):
        """Should also work with 'exploit_suggest_data' key."""
        scan_results = {
            "scanner_data": {
                "host1": {
                    "ports": [
                        {"port": 21, "protocol": "tcp", "service": "ftp"},
                    ]
                }
            },
            "exploit_suggest_data": {
                "suggestions": [
                    {"edb_id": "EDB-17491", "service": "ftp", "cve_id": "CVE-2011-2523"},
                ]
            },
        }
        script = generate_msf_script_full("test.com", scan_results)
        assert script.exploit_count >= 1
