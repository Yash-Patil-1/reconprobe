"""Tests for reconprobe.webhook."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from reconprobe.webhook import (
    ScanResultSummary,
    SlackConfig,
    DiscordConfig,
    EmailConfig,
    WebhookConfig,
    send_slack,
    send_discord,
    send_email,
    dispatch_webhooks,
    build_summary_from_report,
)


@pytest.fixture
def sample_summary() -> ScanResultSummary:
    return ScanResultSummary(
        domain="example.com",
        total_subdomains=42,
        total_open_ports=15,
        total_vulns=3,
        total_loot_items=7,
        total_osint_findings=12,
        scan_duration_seconds=120.5,
        timestamp="2025-01-15T10:30:00",
        scan_id="abc123",
    )


class TestSlack:
    @pytest.mark.asyncio
    async def test_send_slack_success(self, sample_summary):
        config = SlackConfig(webhook_url="https://hooks.slack.com/services/TEST")
        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_post.return_value.__aenter__.return_value = mock_resp

            result = await send_slack(sample_summary, config)
            assert result is True

            # Verify payload structure
            call_kwargs = mock_post.call_args[1]
            assert "blocks" in call_kwargs["json"]
            blocks = call_kwargs["json"]["blocks"]
            assert any("ReconProbe Scan Complete" in str(b) for b in blocks)

    @pytest.mark.asyncio
    async def test_send_slack_failure(self, sample_summary):
        config = SlackConfig(webhook_url="https://hooks.slack.com/services/TEST")
        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_resp = AsyncMock()
            mock_resp.status = 400
            mock_resp.text = AsyncMock(return_value="Bad Request")
            mock_post.return_value.__aenter__.return_value = mock_resp

            result = await send_slack(sample_summary, config)
            assert result is False

    @pytest.mark.asyncio
    async def test_send_slack_timeout(self, sample_summary):
        config = SlackConfig(webhook_url="https://hooks.slack.com/services/TEST")
        with patch("aiohttp.ClientSession.post", side_effect=TimeoutError):
            result = await send_slack(sample_summary, config)
            assert result is False


class TestDiscord:
    @pytest.mark.asyncio
    async def test_send_discord_success(self, sample_summary):
        config = DiscordConfig(webhook_url="https://discord.com/api/webhooks/TEST")
        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_resp = AsyncMock()
            mock_resp.status = 204
            mock_post.return_value.__aenter__.return_value = mock_resp

            result = await send_discord(sample_summary, config)
            assert result is True

    @pytest.mark.asyncio
    async def test_send_discord_zero_vulns_uses_green(self, sample_summary):
        """No vulns → green embed color (0x00FF00)."""
        summary = ScanResultSummary(
            domain="safe.com",
            total_subdomains=5, total_open_ports=2, total_vulns=0,
            total_loot_items=0, total_osint_findings=0, scan_duration_seconds=30,
        )
        config = DiscordConfig(webhook_url="https://discord.com/api/webhooks/TEST")
        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_resp = AsyncMock()
            mock_resp.status = 204
            mock_post.return_value.__aenter__.return_value = mock_resp

            await send_discord(summary, config)
            payload = mock_post.call_args[1]["json"]
            assert payload["embeds"][0]["color"] == 0x00FF00

    @pytest.mark.asyncio
    async def test_send_discord_many_vulns_uses_red(self, sample_summary):
        """5+ vulns → red embed color (0xFF0000)."""
        summary = ScanResultSummary(
            domain="vuln.com",
            total_subdomains=10, total_open_ports=5, total_vulns=7,
            total_loot_items=3, total_osint_findings=0, scan_duration_seconds=60,
        )
        config = DiscordConfig(webhook_url="https://discord.com/api/webhooks/TEST")
        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_resp = AsyncMock()
            mock_resp.status = 204
            mock_post.return_value.__aenter__.return_value = mock_resp

            await send_discord(summary, config)
            payload = mock_post.call_args[1]["json"]
            assert payload["embeds"][0]["color"] == 0xFF0000


class TestEmail:
    @pytest.mark.asyncio
    async def test_send_email_success(self, sample_summary):
        config = EmailConfig(
            smtp_host="smtp.example.com",
            smtp_port=587,
            from_addr="reconprobe@example.com",
            to_addrs=["admin@example.com"],
        )
        with patch("smtplib.SMTP") as mock_smtp:
            instance = mock_smtp.return_value.__enter__.return_value
            result = await send_email(sample_summary, config)
            assert result is True
            assert instance.send_message.called

    @pytest.mark.asyncio
    async def test_send_email_smtp_error(self, sample_summary):
        config = EmailConfig(
            smtp_host="smtp.example.com",
            from_addr="reconprobe@example.com",
            to_addrs=["admin@example.com"],
        )
        with patch("smtplib.SMTP") as mock_smtp:
            instance = mock_smtp.return_value.__enter__.return_value
            instance.send_message.side_effect = ConnectionRefusedError
            result = await send_email(sample_summary, config)
            assert result is False


class TestDispatchWebhooks:
    @pytest.mark.asyncio
    async def test_dispatch_all_targets(self, sample_summary):
        config = WebhookConfig(
            slack=SlackConfig(webhook_url="https://hooks.slack.com/TEST"),
            discord=DiscordConfig(webhook_url="https://discord.com/api/webhooks/TEST"),
            email=EmailConfig(
                smtp_host="smtp.example.com",
                from_addr="test@example.com",
                to_addrs=["admin@example.com"],
            ),
        )
        with (
            patch("reconprobe.webhook.send_slack", return_value=True),
            patch("reconprobe.webhook.send_discord", return_value=True),
            patch("reconprobe.webhook.send_email", return_value=True),
        ):
            results = await dispatch_webhooks(sample_summary, config)
            assert results == {"slack": True, "discord": True, "email": True}

    @pytest.mark.asyncio
    async def test_dispatch_empty_config(self, sample_summary):
        config = WebhookConfig()
        results = await dispatch_webhooks(sample_summary, config)
        assert results == {}

    @pytest.mark.asyncio
    async def test_dispatch_slack_only(self, sample_summary):
        config = WebhookConfig(slack=SlackConfig(webhook_url="https://hooks.slack.com/TEST"))
        with patch("reconprobe.webhook.send_slack", return_value=True):
            results = await dispatch_webhooks(sample_summary, config)
            assert results == {"slack": True}


class TestBuildSummaryFromReport:
    def test_build_from_full_report(self):
        report = {
            "target": {"domain": "example.com"},
            "subdomain_enumeration": {"total_found": 25},
            "port_scan": {
                "results": {
                    "example.com": {"open_ports": [80, 443]},
                    "www.example.com": {"open_ports": [8080]},
                },
            },
            "vulnerability_scan": {"total_cves": 5},
            "loot": {"total_count": 3},
            "osint": {"total_findings": 10},
            "scan_info": {
                "duration_seconds": 90.0,
                "end_time": "2025-01-15T10:30:00",
            },
        }
        summary = build_summary_from_report(report)
        assert summary.domain == "example.com"
        assert summary.total_subdomains == 25
        assert summary.total_open_ports == 3  # 2 + 1
        assert summary.total_vulns == 5
        assert summary.total_loot_items == 3
        assert summary.total_osint_findings == 10
        assert summary.scan_duration_seconds == 90.0

    def test_build_with_backward_compat_ports(self):
        """Handle both 'open_ports' and 'ports' keys."""
        report = {
            "domain": "test.com",
            "port_scan": {
                "results": {
                    "test.com": {"ports": [22, 80, 443]},
                },
            },
            "scan_info": {"duration_seconds": 0},
        }
        summary = build_summary_from_report(report)
        assert summary.total_open_ports == 3

    def test_build_minimal_report(self):
        report = {"domain": "minimal.com", "scan_info": {"duration_seconds": 0}}
        summary = build_summary_from_report(report)
        assert summary.total_subdomains == 0
        assert summary.total_open_ports == 0
        assert summary.scan_id
