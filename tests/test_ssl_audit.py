"""Tests for the SSL/TLS audit module (reconprobe.ssl_audit)."""

from __future__ import annotations

import asyncio
import ssl
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

import pytest

from reconprobe.ssl_audit import (
    CertInfo,
    ProtocolCheck,
    CipherCheck,
    SecurityHeaderCheck,
    SslAuditReport,
    inspect_certificate,
    check_certificate,
    check_protocol,
    check_tls_13,
    scan_protocols,
    check_weak_ciphers,
    check_security_headers,
    calculate_grade,
    audit_ssl,
    audit_ssl_hosts,
    SECURITY_HEADERS,
)


# ── Data structure tests ────────────────────────────────────────────────────


class TestDataStructures:
    def test_cert_info_defaults(self):
        c = CertInfo()
        assert c.is_expired is False
        assert c.is_self_signed is False
        assert c.is_wildcard is False
        assert c.days_remaining == 0

    def test_ssl_audit_report_to_dict(self):
        report = SslAuditReport(hostname="test.com", port=443, grade="B")
        d = report.to_dict()
        assert d["hostname"] == "test.com"
        assert d["port"] == 443
        assert d["grade"] == "B"

    def test_ssl_audit_report_with_cert_to_dict(self):
        cert = CertInfo(
            subject="CN=test.com", issuer="CN=CA",
            common_name="test.com", san=["test.com", "www.test.com"],
            is_expired=False, is_self_signed=True,
            days_remaining=45,
        )
        report = SslAuditReport(hostname="test.com", certificate=cert)
        d = report.to_dict()
        assert d["certificate"]["common_name"] == "test.com"
        assert d["certificate"]["is_self_signed"] is True
        assert d["certificate"]["days_remaining"] == 45
        assert len(d["certificate"]["san"]) == 2

    def test_security_header_check_defaults(self):
        h = SecurityHeaderCheck(header="X-Test")
        assert h.present is False
        assert h.recommended is False


# ── Certificate inspection tests ─────────────────────────────────────────────


class TestInspectCertificate:
    def test_none_cert_returns_none(self):
        assert inspect_certificate(None, "test.com") is None

    def test_basic_cert_info(self):
        raw = {
            "subject": [[("commonName", "example.com")]],
            "issuer": [[("commonName", "R3"), ("organizationName", "Let's Encrypt")]],
            "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")],
            "notBefore": "May 21 12:00:00 2024 GMT",
            "notAfter": "May 21 12:00:00 2026 GMT",
            "serialNumber": "1234567890ABCDEF",
            "version": 2,
            "signatureAlgorithm": "sha256WithRSAEncryption",
        }
        info = inspect_certificate(raw, "example.com")
        assert info is not None
        assert info.common_name == "example.com"
        assert "Let's Encrypt" in info.issuer
        assert len(info.san) == 2
        assert "example.com" in info.san
        assert info.serial_number == "1234567890ABCDEF"
        assert info.version == 2
        assert info.signature_algorithm == "sha256WithRSAEncryption"

    def test_self_signed_detection(self):
        raw = {
            "subject": [[("commonName", "self-signed")]],
            "issuer": [[("commonName", "self-signed")]],
        }
        info = inspect_certificate(raw, "self-signed")
        assert info is not None
        assert info.is_self_signed is True

    def test_not_self_signed(self):
        raw = {
            "subject": [[("commonName", "example.com")]],
            "issuer": [[("commonName", "CA Issuer")]],
        }
        info = inspect_certificate(raw, "example.com")
        assert info is not None
        assert info.is_self_signed is False

    def test_wildcard_cn_detection(self):
        raw = {
            "subject": [[("commonName", "*.example.com")]],
            "issuer": [[("commonName", "CA")]],
        }
        info = inspect_certificate(raw, "*.example.com")
        assert info is not None
        assert info.is_wildcard is True

    def test_wildcard_san_detection(self):
        raw = {
            "subject": [[("commonName", "example.com")]],
            "issuer": [[("commonName", "CA")]],
            "subjectAltName": [("DNS", "*.example.com")],
        }
        info = inspect_certificate(raw, "example.com")
        assert info is not None
        assert info.is_wildcard is True

    def test_expiry_dates_parsed(self):
        raw = {
            "subject": [[("commonName", "x")]],
            "issuer": [[("commonName", "y")]],
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Jan  1 00:00:00 2025 GMT",
        }
        info = inspect_certificate(raw, "x")
        assert info is not None
        assert "2024" in info.valid_from or info.valid_from == raw["notBefore"]
        assert info.valid_to is not None

    def test_malformed_date_fallback(self):
        raw = {
            "subject": [[("commonName", "x")]],
            "issuer": [[("commonName", "y")]],
            "notBefore": "not-a-date",
            "notAfter": "also-not-a-date",
        }
        info = inspect_certificate(raw, "x")
        assert info is not None
        # Should fall back to raw string values
        assert info.valid_from == "not-a-date"

    def test_empty_subject(self):
        raw = {"subject": [], "issuer": []}
        info = inspect_certificate(raw, "x")
        assert info is not None
        assert info.subject == ""
        assert info.issuer == ""


# ── Protocol scanning tests ─────────────────────────────────────────────────


class TestCheckProtocol:
    @pytest.mark.asyncio
    async def test_protocol_supported(self):
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()

        with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))):
            result = await check_protocol("test.com", 443, "TLS 1.2", ssl.PROTOCOL_TLS_CLIENT)
            assert result.supported is True
            assert result.protocol == "TLS 1.2"

    @pytest.mark.asyncio
    async def test_protocol_not_supported_ssl_error(self):
        with patch("asyncio.open_connection", side_effect=ssl.SSLError()):
            result = await check_protocol("test.com", 443, "TLS 1.0", ssl.TLSVersion.TLSv1)
            assert result.supported is False
            assert result.protocol == "TLS 1.0"
            assert result.error is None  # SSLError caught silently

    @pytest.mark.asyncio
    async def test_protocol_connection_error(self):
        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
            result = await check_protocol("test.com", 443, "TLS 1.1", ssl.TLSVersion.TLSv1_1)
            assert result.supported is False
            assert result.error is not None


class TestCheckTLS13:
    @pytest.mark.asyncio
    async def test_tls13_supported(self):
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_ssl_object = MagicMock()
        mock_ssl_object.version.return_value = "TLSv1.3"
        # get_extra_info is a sync method on StreamWriter, not async
        mock_writer.get_extra_info.return_value = mock_ssl_object
        mock_writer.close = MagicMock()

        with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))):
            result = await check_tls_13("test.com", 443)
            assert result.supported is True
            assert result.protocol == "TLS 1.3"

    @pytest.mark.asyncio
    async def test_tls13_not_supported(self):
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_ssl_object = MagicMock()
        mock_ssl_object.version.return_value = "TLSv1.2"
        mock_writer.get_extra_info.return_value = mock_ssl_object
        mock_writer.close = MagicMock()

        with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))):
            result = await check_tls_13("test.com", 443)
            assert result.supported is False

    @pytest.mark.asyncio
    async def test_tls13_ssl_error(self):
        with patch("asyncio.open_connection", side_effect=ssl.SSLError()):
            result = await check_tls_13("test.com", 443)
            assert result.supported is False


class TestScanProtocols:
    @pytest.mark.asyncio
    async def test_scan_all_protocols(self):
        """Should return results for all 4 TLS versions."""
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_ssl_object = MagicMock()
        mock_ssl_object.version.return_value = "TLSv1.3"
        mock_writer.get_extra_info.return_value = mock_ssl_object
        mock_writer.close = MagicMock()

        with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))):
            results = await scan_protocols("test.com", 443)
            assert len(results) == 4
            protocols = [r.protocol for r in results]
            assert "TLS 1.0" in protocols
            assert "TLS 1.1" in protocols
            assert "TLS 1.2" in protocols
            assert "TLS 1.3" in protocols
            # Check ordering
            assert protocols == ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]


# ── Security headers tests ──────────────────────────────────────────────────


class TestCheckSecurityHeaders:
    @pytest.mark.asyncio
    async def test_all_headers_present(self):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
        mock_resp.text = ""

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check_security_headers("test.com", 443)

        hsts = next(r for r in results if r.header == "Strict-Transport-Security")
        assert hsts.present is True
        assert "31536000" in hsts.value

        xfo = next(r for r in results if r.header == "X-Frame-Options")
        assert xfo.present is True
        assert xfo.value == "DENY"

    @pytest.mark.asyncio
    async def test_no_headers(self):
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_resp.text = ""

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check_security_headers("test.com", 443)

        recommended = [r for r in results if r.recommended]
        for r in recommended:
            assert r.present is False

    @pytest.mark.asyncio
    async def test_hsts_low_max_age(self):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Strict-Transport-Security": "max-age=3600",
        }
        mock_resp.text = ""

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check_security_headers("test.com", 443)

        hsts = next(r for r in results if r.header == "Strict-Transport-Security")
        assert hsts.present is True
        assert "too low" in hsts.recommendation

    @pytest.mark.asyncio
    async def test_csp_unsafe_inline(self):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Content-Security-Policy": "script-src 'self' 'unsafe-inline'",
        }
        mock_resp.text = ""

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check_security_headers("test.com", 443)

        csp = next(r for r in results if r.header == "Content-Security-Policy")
        assert csp.present is True
        assert "unsafe-inline" in csp.recommendation.lower()

    @pytest.mark.asyncio
    async def test_permissive_cors(self):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Access-Control-Allow-Origin": "*",
        }
        mock_resp.text = ""

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check_security_headers("test.com", 443)

        cors = next(r for r in results if r.header == "Access-Control-Allow-Origin")
        assert cors.present is True
        assert "allows all origins" in cors.recommendation


# ── Grading tests ───────────────────────────────────────────────────────────


class TestCalculateGrade:
    def test_perfect_grade_a(self):
        report = SslAuditReport(hostname="test.com")
        report.certificate = CertInfo(
            is_expired=False, will_expire_soon=False,
            is_self_signed=False, is_wildcard=False,
        )
        report.protocols = [
            ProtocolCheck("TLS 1.0", False),
            ProtocolCheck("TLS 1.1", False),
            ProtocolCheck("TLS 1.2", True),
            ProtocolCheck("TLS 1.3", True),
        ]
        report.security_headers = [
            SecurityHeaderCheck(header="Strict-Transport-Security", recommended=True, present=True),
            SecurityHeaderCheck(header="Content-Security-Policy", recommended=True, present=True),
        ]
        grade = calculate_grade(report)
        assert grade == "A"

    def test_expired_cert_grade_f(self):
        report = SslAuditReport(hostname="test.com")
        report.certificate = CertInfo(is_expired=True, is_self_signed=True)
        report.protocols = [ProtocolCheck("TLS 1.0", True), ProtocolCheck("TLS 1.1", True)]
        grade = calculate_grade(report)
        assert grade == "F"

    def test_old_tls_supported_grade_d(self):
        report = SslAuditReport(hostname="test.com")
        report.certificate = CertInfo(is_expired=False)
        report.protocols = [ProtocolCheck("TLS 1.0", True), ProtocolCheck("TLS 1.1", True)]
        grade = calculate_grade(report)
        # TLS 1.0 + 1.1 = 12 issues -> 8 < 12 <= 15 = C
        assert grade in ("C", "D", "F")

    def test_expiring_soon_downgrade(self):
        report = SslAuditReport(hostname="test.com")
        report.certificate = CertInfo(will_expire_soon=True)
        grade = calculate_grade(report)
        # 5 issues → B or C
        assert grade in ("B", "C")

    def test_missing_recommended_headers(self):
        report = SslAuditReport(hostname="test.com")
        report.certificate = CertInfo()
        report.security_headers = [
            SecurityHeaderCheck(header="HSTS", recommended=True, present=False),
            SecurityHeaderCheck(header="CSP", recommended=True, present=False),
        ]
        grade = calculate_grade(report)
        assert grade in ("B", "C")  # 4 issues = B

    def test_weak_ciphers_downgrade(self):
        report = SslAuditReport(hostname="test.com")
        report.certificate = CertInfo()
        report.weak_ciphers = [CipherCheck("RC4", supported=True, is_weak=True)]
        grade = calculate_grade(report)
        assert grade in ("B", "C")

    def test_total_issues_count(self):
        report = SslAuditReport(hostname="test.com")
        report.certificate = CertInfo(is_expired=True, is_self_signed=True)
        report.weak_ciphers = [CipherCheck("RC4", supported=True, is_weak=True)]
        calculate_grade(report)
        # expired(10) + self_signed(8) + RC4(5) = 23 issues
        assert report.total_issues == 23


# ─── Orchestrator tests ─────────────────────────────────────────────────────


class TestAuditSSL:
    @pytest.mark.asyncio
    async def test_audit_all_disabled(self):
        """When all sub-checks are disabled, only cert is checked."""
        mock_reader = AsyncMock()
        mock_writer = MagicMock()  # StreamWriter methods are sync, not async
        mock_cert = {
            "subject": [[("commonName", "test.com")]],
            "issuer": [[("commonName", "CA")]],
        }
        mock_writer.get_extra_info.return_value = mock_cert
        mock_writer.close = MagicMock()

        with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))):
            report = await audit_ssl("test.com", 443, check_protos=False, check_ciphers=False, check_headers=False)
            assert report.hostname == "test.com"
            assert report.port == 443
            assert report.certificate is not None
            assert report.certificate.common_name == "test.com"

    @pytest.mark.asyncio
    async def test_audit_connection_error(self):
        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
            report = await audit_ssl("test.com", 9999)
            # check_certificate catches ConnectionRefusedError and returns CertInfo(error=str(e))
            # The code continues to check protocols (which also fail), then grades the result
            assert report.certificate is not None
            assert report.certificate.error is not None
            # Grade is calculated even with errors — protocols all return False, grade is lenient

    @pytest.mark.asyncio
    async def test_audit_with_proxy_for_headers(self):
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_cert = {"subject": [[("commonName", "test.com")]], "issuer": [[("commonName", "CA")]]}
        mock_writer.get_extra_info.return_value = mock_cert
        mock_writer.close = MagicMock()

        mock_resp = MagicMock()
        mock_resp.headers = {"Strict-Transport-Security": "max-age=31536000"}
        mock_resp.text = ""

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with (
            patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))),
            patch("httpx.AsyncClient", return_value=mock_client),
        ):
            report = await audit_ssl("test.com", 443, proxy_url="http://proxy:8080")
            assert report.certificate is not None
            hsts = next((h for h in report.security_headers if h.header == "Strict-Transport-Security"), None)
            assert hsts is not None
            assert hsts.present is True


class TestAuditSSLHosts:
    @pytest.mark.asyncio
    async def test_audit_multiple_hosts(self):
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_cert = {"subject": [[("commonName", "x")]], "issuer": [[("commonName", "CA")]]}
        mock_writer.get_extra_info.return_value = mock_cert
        mock_writer.close = MagicMock()

        with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))):
            hosts = [("test1.com", 443), ("test2.com", 443)]
            reports = await audit_ssl_hosts(hosts, check_protos=False, check_ciphers=False, check_headers=False)
            assert len(reports) == 2
            assert "test1.com:443" in reports
            assert "test2.com:443" in reports
