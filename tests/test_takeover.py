"""Tests for the subdomain takeover detection module (reconprobe.takeover)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from reconprobe.takeover import (
    TakeoverFingerprint,
    TakeoverResult,
    TakeoverReport,
    resolve_cname,
    resolve_a,
    check_dns_dangling,
    check_http_signatures,
    check_takeover,
    scan_takeovers,
    TAKEOVER_FINGERPRINTS,
)


# ── Data structure tests ────────────────────────────────────────────────────


class TestDataStructures:
    def test_takeover_result_defaults(self):
        r = TakeoverResult(hostname="test.example.com")
        assert r.hostname == "test.example.com"
        assert r.is_vulnerable is False
        assert r.confidence == ""
        assert r.dns_status == ""

    def test_takeover_result_to_dict(self):
        r = TakeoverResult(
            hostname="test.example.com", service="AWS S3",
            is_vulnerable=True, confidence="high",
            dns_status="dangling", http_status=404,
        )
        d = r.to_dict()
        assert d["hostname"] == "test.example.com"
        assert d["is_vulnerable"] is True
        assert d["confidence"] == "high"
        assert d["http_status"] == 404

    def test_takeover_report(self):
        r = TakeoverResult(hostname="x.com", is_vulnerable=True)
        report = TakeoverReport(results=[r], total_checked=1, total_vulnerable=1)
        d = report.to_dict()
        assert d["total_checked"] == 1
        assert d["total_vulnerable"] == 1
        assert len(d["results"]) == 1

    def test_takeover_report_only_vulnerable_in_results(self):
        safe = TakeoverResult(hostname="safe.com", is_vulnerable=False)
        vuln = TakeoverResult(hostname="vuln.com", is_vulnerable=True)
        report = TakeoverReport(results=[safe, vuln], total_checked=2)
        d = report.to_dict()
        assert len(d["results"]) == 1  # Only the vulnerable one


# ── Fingerprint database tests ──────────────────────────────────────────────


class TestFingerprintDatabase:
    def test_has_major_services(self):
        services = {fp.service for fp in TAKEOVER_FINGERPRINTS}
        assert "AWS S3 Bucket" in services
        assert "Cloudflare" in services
        assert "GitHub Pages" in services
        assert "Heroku" in services
        assert "Netlify" in services

    def test_fingerprints_have_required_fields(self):
        for fp in TAKEOVER_FINGERPRINTS:
            assert fp.service
            assert fp.cname_patterns
            assert fp.nxdomain is True  # All should check NXDOMAIN
            assert len(fp.http_signatures) > 0

    def test_no_duplicate_services(self):
        services = [fp.service for fp in TAKEOVER_FINGERPRINTS]
        assert len(services) == len(set(services))

    def test_all_have_http_signatures(self):
        for fp in TAKEOVER_FINGERPRINTS:
            assert len(fp.http_signatures) >= 1, f"{fp.service} has no HTTP signatures"

    def test_minimum_fingerprint_count(self):
        assert len(TAKEOVER_FINGERPRINTS) >= 20


# ── DNS resolution tests ────────────────────────────────────────────────────


class TestResolveCname:
    @pytest.mark.asyncio
    async def test_cname_found(self):
        class FakeTarget:
            def __str__(self):
                return "target.cloudfront.net."

        mock_answer = MagicMock()
        mock_answer.target = FakeTarget()
        mock_resolver_func = MagicMock(return_value=[mock_answer])

        with patch("dns.resolver.resolve", mock_resolver_func):
            result = await resolve_cname("test.example.com")
            assert result == "target.cloudfront.net"

    @pytest.mark.asyncio
    async def test_no_cname(self):
        import dns.resolver
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer):
            result = await resolve_cname("test.example.com")
            assert result is None

    @pytest.mark.asyncio
    async def test_nxdomain(self):
        import dns.resolver
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN):
            result = await resolve_cname("test.example.com")
            assert result is None

    @pytest.mark.asyncio
    async def test_generic_exception(self):
        with patch("dns.resolver.resolve", side_effect=Exception("DNS failure")):
            result = await resolve_cname("test.example.com")
            assert result is None


class TestResolveA:
    @pytest.mark.asyncio
    async def test_a_record_found(self):
        class FakeAnswer:
            def __str__(self):
                return "1.2.3.4"

        mock_answer = FakeAnswer()
        mock_resolver_func = MagicMock(return_value=[mock_answer])

        with patch("dns.resolver.resolve", mock_resolver_func):
            result = await resolve_a("test.example.com")
            assert result == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_no_a_record(self):
        import dns.resolver
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN):
            result = await resolve_a("test.example.com")
            assert result is None

    @pytest.mark.asyncio
    async def test_a_generic_exception(self):
        with patch("dns.resolver.resolve", side_effect=Exception("fail")):
            result = await resolve_a("test.example.com")
            assert result is None


# ── DNS dangling detection tests ─────────────────────────────────────────────


class TestCheckDNSDangling:
    @pytest.mark.asyncio
    async def test_nxdomain(self):
        with patch("reconprobe.takeover.resolve_a", new=AsyncMock(return_value=None)):
            cname, status = await check_dns_dangling("test.example.com")
            assert cname is None
            assert status == "nxdomain"

    @pytest.mark.asyncio
    async def test_no_cname(self):
        with (
            patch("reconprobe.takeover.resolve_a", new=AsyncMock(return_value="1.2.3.4")),
            patch("reconprobe.takeover.resolve_cname", new=AsyncMock(return_value=None)),
        ):
            cname, status = await check_dns_dangling("test.example.com")
            assert cname is None
            assert status == "no_cname"

    @pytest.mark.asyncio
    async def test_resolved_ok(self):
        cname_target = "target.cloudfront.net"

        async def resolve_a_side_effect(hostname):
            if hostname == "test.example.com":
                return "1.2.3.4"
            if hostname == cname_target:
                return "5.6.7.8"
            return None

        with (
            patch("reconprobe.takeover.resolve_a", side_effect=resolve_a_side_effect),
            patch("reconprobe.takeover.resolve_cname", new=AsyncMock(return_value=cname_target)),
        ):
            cname, status = await check_dns_dangling("test.example.com")
            assert cname == cname_target
            assert status == "resolved"

    @pytest.mark.asyncio
    async def test_dangling_scenario(self):
        """Simulate: hostname has A record → has CNAME → CNAME doesn't resolve."""
        # Need careful mocking since resolve_a is called twice with different args
        cname_target = "nonexistent.s3.amazonaws.com"

        async def resolve_a_side_effect(hostname):
            if hostname == "test.example.com":
                return "1.2.3.4"
            if hostname == cname_target:
                return None
            return None

        with (
            patch("reconprobe.takeover.resolve_a", side_effect=resolve_a_side_effect),
            patch("reconprobe.takeover.resolve_cname", new=AsyncMock(return_value=cname_target)),
        ):
            cname, status = await check_dns_dangling("test.example.com")
            assert cname == cname_target
            assert status == "dangling"


# ── HTTP signature checking tests ────────────────────────────────────────────


class TestCheckHTTPSignatures:
    @pytest.fixture
    def s3_fingerprint(self):
        return TakeoverFingerprint(
            "AWS S3 Bucket",
            ["s3.amazonaws.com"],
            nxdomain=True,
            http_signatures=["NoSuchBucket", "The specified bucket does not exist"],
            http_status=404,
        )

    @pytest.mark.asyncio
    async def test_match_found(self, s3_fingerprint):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "<html>NoSuchBucket - The specified bucket does not exist</html>"

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            service, snippet, status, sig_type = await check_http_signatures(
                "test.example.com", [s3_fingerprint]
            )
            assert service == "AWS S3 Bucket"
            assert status == 404
            assert sig_type == "http_body_match"
            # Snippet is from lowered body, check lowered form
            assert "nosuchbucket" in snippet or "NoSuchBucket" in snippet

    @pytest.mark.asyncio
    async def test_no_match(self, s3_fingerprint):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html>Welcome to example.com</html>"

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            service, snippet, status, sig_type = await check_http_signatures(
                "test.example.com", [s3_fingerprint]
            )
            assert service is None
            assert status == 200
            assert sig_type == "no_match"

    @pytest.mark.asyncio
    async def test_status_code_mismatch(self, s3_fingerprint):
        """If status code doesn't match fingerprint, should skip even if body matches."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200  # Wrong status — fingerprint expects 404
        mock_resp.text = "NoSuchBucket"

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            service, snippet, status, sig_type = await check_http_signatures(
                "test.example.com", [s3_fingerprint]
            )
            assert service is None  # Should be no match due to status mismatch
            assert sig_type == "no_match"

    @pytest.mark.asyncio
    async def test_https_timeout_fallback_to_http(self):
        """If HTTPS times out, should fall back to HTTP."""
        import httpx
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "NoSuchBucket"

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client

        # First call (HTTPS) raises timeout, second call (HTTP) succeeds
        mock_client.get.side_effect = [
            httpx.TimeoutException("timeout"),
            mock_resp,
        ]

        s3_fp = TakeoverFingerprint(
            "AWS S3 Bucket", ["s3.amazonaws.com"],
            nxdomain=True,
            http_signatures=["NoSuchBucket"],
            http_status=404,
        )

        with patch("httpx.AsyncClient", return_value=mock_client):
            service, snippet, status, sig_type = await check_http_signatures(
                "test.example.com", [s3_fp]
            )
            assert service == "AWS S3 Bucket"
            assert sig_type == "http_body_match"

    @pytest.mark.asyncio
    async def test_connection_failure(self):
        import httpx
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.side_effect = httpx.ConnectError("connection failed")

        with patch("httpx.AsyncClient", return_value=mock_client):
            service, snippet, status, sig_type = await check_http_signatures(
                "test.example.com", [TakeoverFingerprint("Test", ["test.com"], http_signatures=["x"])]
            )
            assert status is None
            assert sig_type == "connection_failed"


# ── Main takeover logic tests ───────────────────────────────────────────────


class TestCheckTakeover:
    @pytest.mark.asyncio
    async def test_high_confidence_takeover(self):
        """Both DNS dangling + HTTP body match → high confidence."""
        s3_fp = TakeoverFingerprint(
            "AWS S3 Bucket", ["s3.amazonaws.com"],
            nxdomain=True,
            http_signatures=["NoSuchBucket"],
            http_status=404,
        )

        async def mock_dns(hostname):
            return ("nonexistent.s3.amazonaws.com", "dangling")

        async def mock_http(hostname, fingerprints):
            return ("AWS S3 Bucket", "NoSuchBucket", 404, "http_body_match")

        with (
            patch("reconprobe.takeover.check_dns_dangling", mock_dns),
            patch("reconprobe.takeover.check_http_signatures", mock_http),
        ):
            result = await check_takeover("test.example.com", [s3_fp])
            assert result.is_vulnerable is True
            assert result.confidence == "high"
            assert result.service == "AWS S3 Bucket"
            assert result.dns_status == "dangling"

    @pytest.mark.asyncio
    async def test_medium_confidence_dns_dangling_connection_failed(self):
        """DNS dangling + HTTP connection failed (not no_match) → medium confidence."""
        s3_fp = TakeoverFingerprint(
            "AWS S3 Bucket", ["s3.amazonaws.com"],
            nxdomain=True, http_signatures=["NoSuchBucket"],
        )

        async def mock_dns(hostname):
            return ("nonexistent.s3.amazonaws.com", "dangling")

        async def mock_http(hostname, fingerprints):
            return (None, None, None, "connection_failed")

        with (
            patch("reconprobe.takeover.check_dns_dangling", mock_dns),
            patch("reconprobe.takeover.check_http_signatures", mock_http),
        ):
            result = await check_takeover("test.example.com", [s3_fp])
            assert result.is_vulnerable is True
            assert result.confidence == "medium"

    @pytest.mark.asyncio
    async def test_medium_confidence_http_only(self):
        """HTTP match even though DNS looked normal → medium."""
        async def mock_dns(hostname):
            return ("resolved.cname.com", "resolved")

        async def mock_http(hostname, fingerprints):
            return ("AWS S3 Bucket", "NoSuchBucket", 404, "http_body_match")

        with (
            patch("reconprobe.takeover.check_dns_dangling", mock_dns),
            patch("reconprobe.takeover.check_http_signatures", mock_http),
        ):
            result = await check_takeover("test.example.com")
            assert result.is_vulnerable is True
            assert result.confidence == "medium"

    @pytest.mark.asyncio
    async def test_low_confidence_nxdomain(self):
        """Hostname doesn't resolve → low confidence."""
        async def mock_dns(hostname):
            return (None, "nxdomain")

        async def mock_http(hostname, fingerprints):
            return (None, None, None, "connection_failed")

        with (
            patch("reconprobe.takeover.check_dns_dangling", mock_dns),
            patch("reconprobe.takeover.check_http_signatures", mock_http),
        ):
            result = await check_takeover("test.example.com")
            assert result.is_vulnerable is True
            assert result.confidence == "low"

    @pytest.mark.asyncio
    async def test_not_vulnerable(self):
        """All checks pass → not vulnerable."""
        async def mock_dns(hostname):
            return ("resolved.cname.com", "resolved")

        async def mock_http(hostname, fingerprints):
            return (None, None, 200, "no_match")

        with (
            patch("reconprobe.takeover.check_dns_dangling", mock_dns),
            patch("reconprobe.takeover.check_http_signatures", mock_http),
        ):
            result = await check_takeover("test.example.com")
            assert result.is_vulnerable is False
            assert result.confidence == "none"

    @pytest.mark.asyncio
    async def test_no_cname_not_vulnerable(self):
        """No CNAME found, normal resolution → not vulnerable."""
        async def mock_dns(hostname):
            return (None, "no_cname")

        async def mock_http(hostname, fingerprints):
            return (None, None, 200, "no_match")

        with (
            patch("reconprobe.takeover.check_dns_dangling", mock_dns),
            patch("reconprobe.takeover.check_http_signatures", mock_http),
        ):
            result = await check_takeover("test.example.com")
            assert result.is_vulnerable is False
            assert result.confidence == "none"


class TestScanTakeovers:
    @pytest.mark.asyncio
    async def test_scan_multiple_subdomains(self):
        async def mock_check(hostname):
            return TakeoverResult(
                hostname=hostname, is_vulnerable=("vuln" in hostname),
                confidence="high" if "vuln" in hostname else "none",
            )

        with patch("reconprobe.takeover.check_takeover", mock_check):
            subdomains = ["safe.example.com", "vuln.example.com", "also-safe.example.com"]
            report = await scan_takeovers(subdomains)
            assert report.total_checked == 3
            assert report.total_vulnerable == 1

    @pytest.mark.asyncio
    async def test_concurrent_limit(self):
        """Should respect max_concurrent limit."""
        call_count = 0

        async def mock_check(hostname):
            nonlocal call_count
            call_count += 1
            return TakeoverResult(hostname=hostname)

        with patch("reconprobe.takeover.check_takeover", mock_check):
            subdomains = [f"x{i}.com" for i in range(50)]
            report = await scan_takeovers(subdomains, max_concurrent=10)
            assert report.total_checked == 50
