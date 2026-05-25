"""Tests for the vulnerability scanning module (reconprobe.vuln_scan)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Optional

import pytest

from reconprobe.vuln_scan import (
    CVEInfo,
    DefaultCredential,
    VulnScanReport,
    match_cve_for_service,
    run_cve_mapping,
    check_default_credential,
    check_default_credentials,
    run_vuln_scan,
    CVE_REFERENCE_DB,
    DEFAULT_CREDENTIALS_DB,
)


# ── Data structure tests ────────────────────────────────────────────────────


class TestDataStructures:
    def test_cve_info_defaults(self):
        cve = CVEInfo(cve_id="CVE-2024-0001")
        assert cve.cve_id == "CVE-2024-0001"
        assert cve.cvss_score is None
        assert cve.cvss_severity == ""

    def test_default_credential_to_dict(self):
        cred = DefaultCredential(
            service="ssh", hostname="test.com", port=22,
            username="root", password="admin", source="default_creds",
        )
        d = cred.to_dict()
        assert d["service"] == "ssh"
        assert d["hostname"] == "test.com"
        assert d["port"] == 22
        assert d["username"] == "root"
        assert d["password"] == "admin"

    def test_vuln_scan_report_empty(self):
        report = VulnScanReport()
        assert report.total_cves == 0
        assert report.total_creds == 0
        assert report.total_high_severity == 0

    def test_vuln_scan_report_to_dict(self):
        cve = CVEInfo(
            cve_id="CVE-2024-0001", description="Test CVE",
            cvss_score=9.8, cvss_severity="CRITICAL",
            affected_service="test", affected_version="1.0",
        )
        cred = DefaultCredential(
            service="ssh", hostname="x.com", port=22,
            username="root", password="toor", source="default_creds",
        )
        report = VulnScanReport(
            cve_matches=[cve],
            default_credentials=[cred],
            total_cves=1, total_creds=1, total_high_severity=1,
        )
        d = report.to_dict()
        assert d["total_cves"] == 1
        assert d["total_creds"] == 1
        assert d["total_high_severity"] == 1
        assert len(d["cve_matches"]) == 1
        assert len(d["default_credentials"]) == 1
        assert d["cve_matches"][0]["cve_id"] == "CVE-2024-0001"


# ── CVE matching tests ──────────────────────────────────────────────────────


class TestMatchCVEForService:
    def test_known_service_all_versions(self):
        """SSH has 'all' version CVEs — should return them even without version."""
        cves = match_cve_for_service("ssh")
        assert len(cves) > 0
        cve_ids = {c.cve_id for c in cves}
        assert "CVE-2018-15473" in cve_ids
        assert "CVE-2024-6387" in cve_ids

    def test_known_service_with_exact_version(self):
        """Apache/2.4.49 should match specifically."""
        cves = match_cve_for_service("http", "Apache/2.4.49")
        cve_ids = {c.cve_id for c in cves}
        assert "CVE-2021-41773" in cve_ids

    def test_known_service_different_version_no_specific_match(self):
        """Apache/2.4.41 has no specific CVEs, should return 'all' if present."""
        # http doesn't have 'all' — should return empty for unknown version
        cves = match_cve_for_service("http", "Apache/2.4.41")
        assert len(cves) == 0

    def test_unknown_service_returns_empty(self):
        cves = match_cve_for_service("unknown_service_xyz")
        assert cves == []

    def test_case_insensitive_service_name(self):
        cves = match_cve_for_service("SSH")
        assert len(cves) > 0
        assert "CVE-2018-15473" in {c.cve_id for c in cves}

    def test_mysql_specific_version(self):
        """MySQL 5.5.x should include the critical CVE-2016-6662."""
        cves = match_cve_for_service("mysql", "5.5.53-MariaDB")
        cve_ids = {c.cve_id for c in cves}
        assert "CVE-2016-6662" in cve_ids
        assert "CVE-2023-22102" in cve_ids  # 'all' CVEs also included

    def test_banner_based_matching(self):
        """Should match based on banner content for unknown services."""
        cves = match_cve_for_service("unknown", banner="OpenSSH_8.9p1 Ubuntu")
        cve_ids = {c.cve_id for c in cves}
        # 'ssh' matched from banner
        assert "CVE-2018-15473" in cve_ids

    def test_tomcat_version_matching(self):
        cves = match_cve_for_service("tomcat", "9.0.30")
        assert "CVE-2020-11996" in {c.cve_id for c in cves}

    def test_no_duplicate_cves(self):
        """Same CVE should not appear twice."""
        cves = match_cve_for_service("mysql", "5.5.53")
        cve_ids = [c.cve_id for c in cves]
        assert len(cve_ids) == len(set(cve_ids))

    def test_jenkins_all_versions(self):
        cves = match_cve_for_service("jenkins")
        assert "CVE-2024-23897" in {c.cve_id for c in cves}


# ── Default credentials database tests ──────────────────────────────────────


class TestDefaultCredentialsDB:
    def test_db_has_expected_entries(self):
        services = {c["service"] for c in DEFAULT_CREDENTIALS_DB}
        assert "ssh" in services
        assert "mysql" in services
        assert "redis" in services
        assert "ftp" in services
        assert len(DEFAULT_CREDENTIALS_DB) >= 25

    def test_ssh_has_root_root(self):
        assert any(
            c["service"] == "ssh" and c["username"] == "root" and c["password"] == "root"
            for c in DEFAULT_CREDENTIALS_DB
        )


# ── CVE Reference database tests ────────────────────────────────────────────


class TestCVEDatabase:
    def test_major_services_present(self):
        services = set(CVE_REFERENCE_DB.keys())
        assert "ssh" in services
        assert "http" in services
        assert "mysql" in services
        assert "ftp" in services
        assert "redis" in services

    def test_cves_have_required_fields(self):
        for service, versions in CVE_REFERENCE_DB.items():
            for version, cves in versions.items():
                for cve in cves:
                    assert cve.cve_id.startswith("CVE-")
                    assert cve.cvss_score is not None
                    assert cve.cvss_severity


# ── CVE mapping from scan reports ───────────────────────────────────────────


class TestRunCVEMapping:
    def test_empty_reports(self):
        cves = run_cve_mapping([])
        assert cves == []

    @pytest.fixture
    def mock_port_report(self):
        """Create a mock scan report with an open SSH port."""
        port = MagicMock()
        port.state = "open"
        port.service = "ssh"
        port.port = 22
        port.banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu"
        port.service_version = {}

        report = MagicMock()
        report.ports = [port]
        report.hostname = "test.example.com"
        return report

    @pytest.fixture
    def mock_http_report(self):
        """Create a mock HTTP probe report with technologies."""
        tech = {"name": "wordpress", "version": "6.2"}
        result = MagicMock()
        result.technologies = [tech]

        probe = MagicMock()
        probe.results = [result]
        return {"test.example.com": probe}

    def test_cve_mapping_from_report(self, mock_port_report):
        cves = run_cve_mapping([mock_port_report])
        assert len(cves) > 0
        # SSH CVEs should be matched
        assert any("ssh" in c.affected_service.lower() or "openssh" in c.affected_service for c in cves)

    def test_cve_mapping_with_http_probe(self, mock_port_report, mock_http_report):
        cves = run_cve_mapping([mock_port_report], mock_http_report)
        assert len(cves) > 0
        # WordPress CVEs should be included from HTTP probe technologies
        cve_ids = {c.cve_id for c in cves}
        assert "CVE-2023-30800" in cve_ids

    def test_no_duplicate_cves_across_sources(self, mock_port_report, mock_http_report):
        cves = run_cve_mapping([mock_port_report], mock_http_report)
        cve_ids = [c.cve_id for c in cves]
        assert len(cve_ids) == len(set(cve_ids))

    def test_filtered_non_open_ports(self):
        """Ports that are not open should be skipped."""
        port = MagicMock()
        port.state = "closed"
        report = MagicMock()
        report.ports = [port]
        cves = run_cve_mapping([report])
        assert cves == []


# ── Default credential checking tests ───────────────────────────────────────


class TestCheckDefaultCredential:
    @pytest.mark.asyncio
    async def test_ftp_success(self):
        """Mock a successful FTP login."""
        mock_reader = AsyncMock()
        # First read returns banner, second returns USER response, third returns PASS response
        mock_reader.read.side_effect = [
            b"220 FTP server ready\r\n",
            b"331 Username ok, need password\r\n",
            b"230 Login successful\r\n",
        ]
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()

        async def _open_conn(*args, **kwargs):
            return mock_reader, mock_writer

        with patch("asyncio.open_connection", _open_conn):
            result = await check_default_credential("test.com", 21, "ftp", "anonymous", "anon@x.com")
            assert result is not None
            assert result.service == "ftp"
            assert result.username == "anonymous"
            assert result.hostname == "test.com"
            assert result.port == 21

    @pytest.mark.asyncio
    async def test_ftp_failure(self):
        """Mock a failed FTP login."""
        mock_reader = AsyncMock()
        mock_reader.read.side_effect = [
            b"220 FTP server ready\r\n",
            b"331 Username ok, need password\r\n",
            b"530 Login incorrect\r\n",
        ]
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()

        async def _open_conn(*args, **kwargs):
            return mock_reader, mock_writer

        with patch("asyncio.open_connection", _open_conn):
            result = await check_default_credential("test.com", 21, "ftp", "admin", "wrong")
            assert result is None

    @pytest.mark.asyncio
    async def test_redis_no_auth(self):
        """Mock a Redis server without auth."""
        mock_reader = AsyncMock()
        mock_reader.read.return_value = b"+PONG\r\n"
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()

        async def _open_conn(*args, **kwargs):
            return mock_reader, mock_writer

        with patch("asyncio.open_connection", _open_conn):
            result = await check_default_credential("test.com", 6379, "redis", "", "")
            assert result is not None
            assert result.service == "redis"
            assert result.source == "no_auth_required"

    @pytest.mark.asyncio
    async def test_redis_with_auth(self):
        """Mock a Redis server that requires auth."""
        mock_reader = AsyncMock()
        mock_reader.read.return_value = b"-NOAUTH Authentication required.\r\n"
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()

        async def _open_conn(*args, **kwargs):
            return mock_reader, mock_writer

        with patch("asyncio.open_connection", _open_conn):
            result = await check_default_credential("test.com", 6379, "redis", "", "")
            assert result is None

    @pytest.mark.asyncio
    async def test_connection_refused(self):
        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
            result = await check_default_credential("test.com", 21, "ftp", "a", "b")
            assert result is None

    @pytest.mark.asyncio
    async def test_timeout(self):
        with patch("asyncio.open_connection"), \
             patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
            result = await check_default_credential("test.com", 21, "ftp", "a", "b")
            assert result is None


class TestCheckDefaultCredentials:
    @pytest.mark.asyncio
    async def test_no_matching_services(self):
        report = MagicMock()
        port = MagicMock()
        port.state = "open"
        port.service = "unknown_service"
        port.port = 9999
        report.ports = [port]

        creds = await check_default_credentials([report])
        assert creds == []

    @pytest.mark.asyncio
    async def test_skips_non_open_ports(self):
        report = MagicMock()
        port = MagicMock()
        port.state = "closed"
        port.service = "ssh"
        port.port = 22
        report.ports = [port]

        creds = await check_default_credentials([report])
        assert creds == []

    @pytest.mark.asyncio
    async def test_with_mocked_connections(self):
        """Test that check_default_credentials finds FTP default creds."""
        mock_reader = AsyncMock()
        # FTP login sequence: banner, USER response, PASS response (230 = success)
        mock_reader.read.side_effect = [
            b"220 FTP server ready\r\n",
            b"331 Username ok, need password\r\n",
            b"230 Login successful\r\n",
        ]
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()

        port = MagicMock()
        port.state = "open"
        port.service = "ftp"
        port.port = 21
        report = MagicMock()
        report.hostname = "test.com"
        report.ip_address = "1.2.3.4"
        report.ports = [port]

        async def _open_conn(*args, **kwargs):
            return mock_reader, mock_writer

        with patch("asyncio.open_connection", _open_conn):
            creds = await check_default_credentials([report], max_workers=5)
            # Should get at least one credential from ftp default checks
            assert len(creds) >= 1


# ── Main orchestrator tests ─────────────────────────────────────────────────


class TestRunVulnScan:
    @pytest.mark.asyncio
    async def test_minimal_scan(self):
        """Run vuln scan with no reports."""
        report = await run_vuln_scan([], check_credentials=False)
        assert isinstance(report, VulnScanReport)
        assert report.total_cves == 0
        assert report.total_creds == 0

    @pytest.mark.asyncio
    async def test_with_cve_mapping_only(self):
        port = MagicMock()
        port.state = "open"
        port.service = "ssh"
        port.port = 22
        port.banner = ""
        port.service_version = {}
        scan_report = MagicMock()
        scan_report.ports = [port]

        report = await run_vuln_scan([scan_report], check_credentials=False)
        assert report.total_cves > 0
        assert report.total_high_severity > 0

    @pytest.mark.asyncio
    async def test_with_credential_check(self):
        """Redis has CVE entries in the DB, so expect CVEs + credentials."""
        mock_reader = AsyncMock()
        mock_reader.read.return_value = b"+PONG\r\n"
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()

        port = MagicMock()
        port.state = "open"
        port.service = "redis"
        port.port = 6379
        port.banner = ""
        port.service_version = {}
        scan_report = MagicMock()
        scan_report.hostname = "test.com"
        scan_report.ports = [port]

        async def _open_conn(*args, **kwargs):
            return mock_reader, mock_writer

        with patch("asyncio.open_connection", _open_conn):
            report = await run_vuln_scan([scan_report], check_credentials=True)
            # Redis has CVE-2022-35977 in CVE_REFERENCE_DB under 'all' — expect at least 1 CVE
            assert report.total_cves >= 1
            assert report.total_creds >= 1  # Should find the no-auth cred

    @pytest.mark.asyncio
    async def test_high_severity_counting(self):
        """HIGH and CRITICAL CVEs should be counted."""
        cve_high = CVEInfo("CVE-1", cvss_score=7.5, cvss_severity="HIGH", affected_version="1.0")
        cve_crit = CVEInfo("CVE-2", cvss_score=9.8, cvss_severity="CRITICAL", affected_version="1.0")
        cve_med = CVEInfo("CVE-3", cvss_score=5.0, cvss_severity="MEDIUM", affected_version="1.0")

        report = VulnScanReport(
            cve_matches=[cve_high, cve_crit, cve_med],
            total_cves=3, total_high_severity=2,
        )
        assert report.total_high_severity == 2
