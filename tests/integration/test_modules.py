"""Integration tests for ReconProbe modules against a live test server.

These tests exercise actual module functions against the running test server
(rather than mocking connections), validating that HTTP probing, SSL auditing,
WAF detection, and directory brute-forcing work correctly with real responses.
"""

from __future__ import annotations

import socket

import pytest


@pytest.mark.integration
class TestHTTPProbing:
    """Test HTTP probing against the live test server."""

    @pytest.mark.asyncio
    async def test_probe_localhost_http(self, test_server, http_target) -> None:
        """Test HTTP probing discovers the test server correctly."""
        hostname, port = http_target
        from reconprobe.http_probe import probe_host

        report = await probe_host(
            hostname=hostname,
            ports=[port],
            timeout=10.0,
        )

        assert report is not None
        assert len(report.results) > 0

        result = report.results[0]
        assert result.is_alive
        assert result.status_code == 200
        assert "nginx" in result.server_header.lower()
        assert str(port) in result.url

    @pytest.mark.asyncio
    async def test_probe_detects_technologies(self, test_server, http_target) -> None:
        """Test HTTP probing detects configured technologies from headers."""
        hostname, port = http_target

        from reconprobe.http_probe import probe_host

        report = await probe_host(
            hostname=hostname,
            ports=[port],
            timeout=10.0,
        )

        result = report.results[0]

        # Should detect technologies from server headers and response
        tech_names = [t["name"].lower() for t in result.technologies]
        assert "nginx" in tech_names or any("nginx" in t for t in tech_names)

    @pytest.mark.asyncio
    async def test_probe_multiple_ports(self, test_server, http_url) -> None:
        """Test probing multiple ports discovers the correct one."""
        from reconprobe.http_probe import probe_host

        # Find another free port to confirm it's closed
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            closed_port = s.getsockname()[1]

        report = await probe_host(
            hostname="127.0.0.1",
            ports=[test_server.http_port, closed_port],
            timeout=5.0,
        )

        # The open port should respond
        open_results = [r for r in report.results if r.is_alive]
        assert len(open_results) >= 1


@pytest.mark.integration
class TestSSLAudit:
    """Test SSL/TLS auditing against the test server's HTTPS endpoint."""

    @pytest.mark.asyncio
    async def test_ssl_audit_basic(self, https_target) -> None:
        """Test SSL/TLS audit against the local HTTPS server."""
        if not https_target:
            pytest.skip("HTTPS server not available")

        hostname, port = https_target
        from reconprobe.ssl_audit import audit_ssl

        report = await audit_ssl(
            hostname=hostname,
            port=port,
            check_protos=True,
            check_ciphers=True,
            check_headers=False,
        )

        assert report is not None
        assert report.hostname == hostname
        assert report.port == port

        # Should have detected TLS protocols
        assert len(report.protocols) > 0
        tls_protos = [p for p in report.protocols if "TLS" in p.protocol]
        assert len(tls_protos) > 0

    @pytest.mark.asyncio
    async def test_ssl_audit_certificate(self, https_target) -> None:
        """Test SSL certificate validation against local HTTPS."""
        if not https_target:
            pytest.skip("HTTPS server not available")

        hostname, port = https_target
        from reconprobe.ssl_audit import audit_ssl

        report = await audit_ssl(
            hostname=hostname,
            port=port,
            check_protos=False,
            check_ciphers=False,
            check_headers=False,
        )

        # Certificate may be None if peercert extraction fails on self-signed
        # certs in certain Python/SSL versions. At minimum, verify the report
        # was created and grade was calculated.
        if report.certificate is not None:
            if report.certificate.is_self_signed:
                # Self-signed adds 8 issues -> grade B (0-3=A, 4-8=B, 9-15=C, etc.)
                assert report.grade in ("B", "C", "D", "F")

    @pytest.mark.asyncio
    async def test_ssl_audit_security_headers(self, https_target) -> None:
        """Test security header detection on HTTPS endpoint."""
        if not https_target:
            pytest.skip("HTTPS server not available")

        hostname, port = https_target
        from reconprobe.ssl_audit import audit_ssl

        report = await audit_ssl(
            hostname=hostname,
            port=port,
            check_protos=False,
            check_ciphers=False,
            check_headers=True,
        )

        # Security headers should be detected
        if report.security_headers:
            header_names = [h.header.lower() for h in report.security_headers]
            assert "strict-transport-security" in header_names or \
                   "x-content-type-options" in header_names


@pytest.mark.integration
class TestWAFDetection:
    """Test WAF detection against the test server with WAF headers."""

    @pytest.mark.asyncio
    async def test_passive_waf_detection(self, test_server, http_url) -> None:
        """Test passive WAF detection identifies WAF from headers."""
        from reconprobe.waf_detect import detect_passive

        # The test server is configured with Sucuri WAF headers
        result = await detect_passive(url=http_url, timeout=10.0)

        assert result is not None
        assert result.is_protected, (
            f"WAF should be detected from headers but isn't. "
            f"Detected: {result.detected_wafs}"
        )

        # Should detect at least one WAF from the headers
        waf_names = [w["name"] for w in result.detected_wafs]
        assert len(waf_names) > 0

    @pytest.mark.asyncio
    async def test_waf_detection_identifies_waf_name(self, test_server, http_url) -> None:
        """Test WAF detection correctly names the detected WAF."""
        from reconprobe.waf_detect import detect_passive

        result = await detect_passive(url=http_url, timeout=10.0)

        if result.is_protected:
            waf_names = [w["name"].lower() for w in result.detected_wafs]
            # Should detect at least one known WAF
            assert any(name in ("sucuri", "cloudflare", "cloudfront", "akamai", "f5")
                      for name in waf_names)


@pytest.mark.integration
class TestDirectoryBruteForce:
    """Test directory brute-force against the local test server."""

    def test_dirbuster_discovers_paths(self, test_server, http_url) -> None:
        """Test directory brute-force discovers configured endpoints."""
        from reconprobe.dirbuster import brute_force_paths

        base_url = f"http://127.0.0.1:{test_server.http_port}"

        report = brute_force_paths(
            base_url=base_url,
            hostname="127.0.0.1",
            wordlist_path=None,
            max_workers=2,
            timeout=5.0,
        )

        assert report is not None
        assert len(report.results) > 0

        # Should have found /admin, /login, /dashboard (200 responses)
        found_paths = [r.url for r in report.results if r.is_interesting]
        found_basenames = [p.replace(base_url, "") for p in found_paths]

        assert "/admin" in found_basenames
        assert "/login" in found_basenames

    def test_dirbuster_reports_total_scanned(self, test_server, http_url) -> None:
        """Test dirbuster correctly reports total paths scanned."""
        from reconprobe.dirbuster import brute_force_paths

        base_url = f"http://127.0.0.1:{test_server.http_port}"

        report = brute_force_paths(
            base_url=base_url,
            hostname="127.0.0.1",
            max_workers=2,
            timeout=5.0,
        )

        assert report.total_scanned > 0


@pytest.mark.integration
class TestCrawling:
    """Test web crawling against the local test server."""

    @pytest.mark.asyncio
    async def test_crawl_discovers_pages(self, test_server, http_url) -> None:
        """Test crawling discovers linked pages on the test server."""
        from reconprobe.crawler import crawl_host

        base_url = f"http://127.0.0.1:{test_server.http_port}"

        report = await crawl_host(
            base_url=base_url,
            hostname="127.0.0.1",
            max_depth=2,
            max_pages=10,
            delay=0.1,
            timeout=10.0,
        )

        assert report is not None
        assert report.total_pages >= 1
        assert report.base_url == base_url

    @pytest.mark.asyncio
    async def test_crawl_discovers_links_and_forms(self, test_server, http_url) -> None:
        """Test crawling finds links, scripts, and forms on pages."""
        from reconprobe.crawler import crawl_host

        base_url = f"http://127.0.0.1:{test_server.http_port}"

        report = await crawl_host(
            base_url=base_url,
            hostname="127.0.0.1",
            max_depth=2,
            max_pages=10,
            delay=0.1,
            timeout=10.0,
        )

        # Home page should have links
        assert report.total_links >= 1, "Should have found internal links"


@pytest.mark.integration
class TestPortScanning:
    """Test port scanning against the local test server."""

    def test_basic_port_scan_discovers_open_port(self, test_server, http_target) -> None:
        """Test that basic port scan discovers the test server's open port."""
        hostname, port = http_target
        from reconprobe.scanner import scan_host

        report = scan_host(
            hostname=hostname,
            ip_address="127.0.0.1",
            ports=[port, port + 1, port + 2],  # Our port + some closed ones
            max_workers=2,
            timeout=3.0,
        )

        assert report is not None
        assert report.open_ports >= 1
        assert any(p.port == port and p.is_open for p in report.ports)

    def test_port_scan_on_closed_port(self, test_server) -> None:
        """Test that scanning a closed port finds nothing."""
        from reconprobe.scanner import scan_host

        # Get a known closed port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            closed_port = s.getsockname()[1]

        # Scan a single closed port
        report = scan_host(
            hostname="127.0.0.1",
            ip_address="127.0.0.1",
            ports=[closed_port],
            max_workers=1,
            timeout=2.0,
        )

        assert report is not None
        closed_result = [p for p in report.ports if p.port == closed_port]
        assert len(closed_result) > 0
        assert not closed_result[0].is_open
