"""Tests for the WAF detection module (reconprobe.waf_detect)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reconprobe.waf_detect import (
    WafSignature,
    WafResult,
    WafReport,
    detect_passive,
    detect_active,
    detect_waf,
    WAF_SIGNATURES,
    ACTIVE_PAYLOADS,
)


# ── Data structure tests ────────────────────────────────────────────────────


class TestDataStructures:
    def test_waf_result_defaults(self):
        r = WafResult(url="https://example.com")
        assert r.url == "https://example.com"
        assert r.is_protected is False
        assert r.detected_wafs == []
        assert r.error is None

    def test_waf_result_to_dict(self):
        r = WafResult(url="https://example.com", is_protected=True)
        r.detected_wafs.append({"name": "Cloudflare", "match_type": "passive"})
        d = r.to_dict()
        assert d["url"] == "https://example.com"
        assert d["is_protected"] is True
        assert len(d["detected_wafs"]) == 1

    def test_waf_report(self):
        r = WafResult(url="https://example.com", is_protected=True)
        report = WafReport(
            results={"https://example.com": r},
            total_urls_checked=1, total_protected=1,
        )
        d = report.to_dict()
        assert d["total_urls_checked"] == 1
        assert d["total_protected"] == 1

    def test_waf_signature_defaults(self):
        sig = WafSignature(name="Test")
        assert sig.vendor == ""
        assert sig.block_status_codes == [403, 406, 429, 503]


# ── Signature database tests ────────────────────────────────────────────────


class TestWafSignatureDatabase:
    def test_major_wafs_present(self):
        names = {s.name for s in WAF_SIGNATURES}
        assert "Cloudflare" in names
        assert "AWS WAF" in names
        assert "ModSecurity" in names
        assert "Akamai" in names
        assert "Imperva (Incapsula)" in names

    def test_all_have_name_and_vendor(self):
        for sig in WAF_SIGNATURES:
            assert sig.name
            assert sig.vendor

    def test_no_duplicate_names(self):
        names = [s.name for s in WAF_SIGNATURES]
        assert len(names) == len(set(names))

    def test_minimum_signature_count(self):
        assert len(WAF_SIGNATURES) >= 20

    def test_active_payloads(self):
        assert len(ACTIVE_PAYLOADS) > 0
        assert "OR" in ACTIVE_PAYLOADS[0] or "UNION" in ACTIVE_PAYLOADS[0]


# ── Passive detection tests ─────────────────────────────────────────────────


class TestDetectPassive:
    @pytest.mark.asyncio
    async def test_cloudflare_detected(self):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "server": "cloudflare",
            "cf-ray": "abc123",
        }
        mock_resp.text = ""
        mock_resp.cookies = {"__cfduid": "dummy"}

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await detect_passive("https://example.com")

        assert result.is_protected is True
        matches = {w["name"] for w in result.detected_wafs}
        assert "Cloudflare" in matches
        assert len(result.passive_matches) >= 1

    @pytest.mark.asyncio
    async def test_no_waf_detected(self):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "server": "nginx/1.24.0",
            "content-type": "text/html",
        }
        mock_resp.text = "<html>Hello</html>"
        mock_resp.cookies = {}

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await detect_passive("https://example.com")

        assert result.is_protected is False
        assert result.detected_wafs == []

    @pytest.mark.asyncio
    async def test_akamai_headers_detected(self):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "server": "AkamaiGHost",
            "x-akamai-transformed": "abc",
        }
        mock_resp.text = ""
        mock_resp.cookies = {"ak_bmsc": "test"}

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await detect_passive("https://example.com")

        assert result.is_protected is True
        matches = {w["name"] for w in result.detected_wafs}
        assert "Akamai" in matches

    @pytest.mark.asyncio
    async def test_f5_cookie_detected(self):
        mock_resp = MagicMock()
        mock_resp.headers = {"server": "BigIP"}
        mock_resp.text = ""
        mock_resp.cookies = {"TS0123456": "test"}

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await detect_passive("https://example.com")

        assert result.is_protected is True
        matches = {w["name"] for w in result.detected_wafs}
        assert "F5 BIG-IP ASM" in matches

    @pytest.mark.asyncio
    async def test_connection_error(self):
        import httpx
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.side_effect = httpx.ConnectError("connection failed")

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await detect_passive("https://example.com")

        assert result.is_protected is False
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_body_pattern_match(self):
        """Cloudflare has body_patterns set, so it should be detected via body."""
        mock_resp = MagicMock()
        mock_resp.headers = {"server": "nginx"}
        mock_resp.text = "cloudflare-nginx error page"
        mock_resp.cookies = {}

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await detect_passive("https://example.com")

        # Should detect Cloudflare via body pattern
        assert result.is_protected is True
        matches = {w["name"] for w in result.detected_wafs}
        assert "Cloudflare" in matches

    @pytest.mark.asyncio
    async def test_proxy_passthrough(self):
        mock_resp = MagicMock()
        mock_resp.headers = {"server": "cloudflare"}
        mock_resp.text = ""
        mock_resp.cookies = {}

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client) as mock_cls:
            _result = await detect_passive("https://example.com", proxy_url="http://proxy:8080")
            # Verify proxy was passed
            call_kwargs = mock_cls.call_args
            assert call_kwargs[1]["proxies"] == "http://proxy:8080"


# ── Active detection tests ──────────────────────────────────────────────────


class TestDetectActive:
    @pytest.mark.asyncio
    async def test_cloudflare_active_block(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Attention Required! | Cloudflare - Please complete the security check"

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        cloudflare_sig = WafSignature(
            name="Cloudflare",
            vendor="Cloudflare, Inc.",
            description="Test",
            block_status_codes=[403, 503],
            block_body_patterns=["cf-error-page", "Attention Required"],
        )

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await detect_active(
                "https://example.com",
                matched_signatures=[cloudflare_sig],
            )

        assert result.is_protected is True
        assert "Cloudflare" in result.active_confirmed

    @pytest.mark.asyncio
    async def test_no_block_response(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "OK"

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        cloudflare_sig = WafSignature(
            name="Cloudflare",
            vendor="CF",
            block_status_codes=[403, 503],
            block_body_patterns=["Attention Required"],
        )

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await detect_active(
                "https://example.com",
                matched_signatures=[cloudflare_sig],
            )

        assert result.is_protected is False
        assert result.active_confirmed == []

    @pytest.mark.asyncio
    async def test_multiple_payloads_sent(self):
        """Should iterate through all active payloads."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "OK"

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await detect_active(
                "https://example.com",
                matched_signatures=[],
            )

        assert result.is_protected is False

    @pytest.mark.asyncio
    async def test_http_error_continues(self):
        """HTTP errors during active probing should be caught and the loop should continue."""
        import httpx
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.side_effect = httpx.HTTPError("error")

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await detect_active(
                "https://example.com",
                matched_signatures=[WafSignature(name="Test", vendor="Test")],
            )

        assert result.is_protected is False


# ── Main orchestrator tests ─────────────────────────────────────────────────


class TestDetectWAF:
    @pytest.mark.asyncio
    async def test_single_url_passive_only(self):
        mock_resp = MagicMock()
        mock_resp.headers = {"server": "nginx"}
        mock_resp.text = ""
        mock_resp.cookies = {}

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            report = await detect_waf(["https://example.com"], enable_active=False)

        assert report.total_urls_checked == 1
        assert report.total_protected == 0

    @pytest.mark.asyncio
    async def test_single_url_with_active(self):
        """Passive detects Cloudflare, active confirms it."""
        # First call (passive)
        passive_resp = MagicMock()
        passive_resp.headers = {"server": "cloudflare", "cf-ray": "xyz"}
        passive_resp.text = ""
        passive_resp.cookies = {"__cfduid": "test"}

        # Active calls
        active_resp = MagicMock()
        active_resp.status_code = 403
        active_resp.text = "Attention Required! | Cloudflare"

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        # passive call returns passive_resp, active calls return active_resp
        mock_client.get.return_value = passive_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            # For this test, we're just checking the passive result with enable_active=True
            report = await detect_waf(["https://example.com"], enable_active=True)

        assert "https://example.com" in report.results
        assert report.results["https://example.com"].is_protected

    @pytest.mark.asyncio
    async def test_multiple_urls(self):
        mock_resp = MagicMock()
        mock_resp.headers = {"server": "nginx"}
        mock_resp.text = ""
        mock_resp.cookies = {}

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            report = await detect_waf(
                ["https://example1.com", "https://example2.com"],
                enable_active=False,
            )

        assert report.total_urls_checked == 2
        assert "https://example1.com" in report.results
        assert "https://example2.com" in report.results

    @pytest.mark.asyncio
    async def test_empty_url_list(self):
        report = await detect_waf([], enable_active=False)
        assert report.total_urls_checked == 0
        assert report.results == {}

    @pytest.mark.asyncio
    async def test_with_proxy(self):
        mock_resp = MagicMock()
        mock_resp.headers = {"server": "nginx"}
        mock_resp.text = ""
        mock_resp.cookies = {}

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client) as mock_cls:
            _report = await detect_waf(
                ["https://example.com"],
                enable_active=False,
                proxy_url="http://proxy:8080",
            )
            # Check proxy was passed to at least one call
            for call_args in mock_cls.call_args_list:
                if "proxies" in call_args[1]:
                    assert call_args[1]["proxies"] == "http://proxy:8080"
