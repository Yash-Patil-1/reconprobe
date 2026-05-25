"""Webhook notification dispatcher.

Supports sending scan notifications to:
  - Slack (webhook URL)
  - Discord (webhook URL)
  - Email (SMTP)

All dispatchers are async and accept a standardised ``ScanResultSummary``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import smtplib
from dataclasses import dataclass, field, asdict
from email.message import EmailMessage
from typing import Optional

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    aiohttp = None  # type: ignore[assignment]
    AIOHTTP_AVAILABLE = False

logger = logging.getLogger(__name__)


# ── Data contract ───────────────────────────────────────────────────────────

@dataclass
class ScanResultSummary:
    """Lightweight summary of a completed scan that webhooks can consume."""
    domain: str
    total_subdomains: int
    total_open_ports: int
    total_vulns: int
    total_loot_items: int
    total_osint_findings: int
    scan_duration_seconds: float
    timestamp: str = ""
    scan_id: str = ""
    extra: dict = field(default_factory=dict)


# ── Dispatch target configuration ───────────────────────────────────────────

@dataclass
class SlackConfig:
    webhook_url: str
    channel: Optional[str] = None
    username: str = "ReconProbe Bot"
    icon_emoji: str = ":shield:"


@dataclass
class DiscordConfig:
    webhook_url: str
    username: str = "ReconProbe"
    avatar_url: str = ""


@dataclass
class EmailConfig:
    smtp_host: str
    from_addr: str
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    use_tls: bool = True
    to_addrs: list[str] = field(default_factory=list)


# ── Dispatchers ─────────────────────────────────────────────────────────────

async def send_slack(
    summary: ScanResultSummary,
    config: SlackConfig,
) -> bool:
    """Send a scan summary to a Slack webhook."""
    if not AIOHTTP_AVAILABLE:
        logger.error("aiohttp not installed. Install with: pip install reconprobe[webhooks]")
        return False
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🛡️ ReconProbe Scan Complete: {summary.domain}"},
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Subdomains:*\n{summary.total_subdomains}"},
                {"type": "mrkdwn", "text": f"*Open Ports:*\n{summary.total_open_ports}"},
                {"type": "mrkdwn", "text": f"*Vulnerabilities:*\n{summary.total_vulns}"},
                {"type": "mrkdwn", "text": f"*Loot Items:*\n{summary.total_loot_items}"},
            ],
        },
    ]

    if summary.total_osint_findings > 0:
        blocks.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*OSINT Findings:*\n{summary.total_osint_findings}"},
            ],
        })

    duration = summary.scan_duration_seconds
    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": f"⏱️ Duration: {duration:.1f}s  |  🆔 {summary.scan_id or 'N/A'}"},
        ],
    })

    payload: dict = {
        "username": config.username,
        "icon_emoji": config.icon_emoji,
        "blocks": blocks,
    }
    if config.channel:
        payload["channel"] = config.channel

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(config.webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    logger.info("Slack notification sent for %s", summary.domain)
                    return True
                body = await resp.text()
                logger.warning("Slack webhook returned %d: %s", resp.status, body[:200])
                return False
    except (asyncio.TimeoutError, aiohttp.ClientError) as e:
        logger.error("Slack webhook error: %s", e)
        return False


async def send_discord(
    summary: ScanResultSummary,
    config: DiscordConfig,
) -> bool:
    """Send a scan summary to a Discord webhook."""
    if not AIOHTTP_AVAILABLE:
        logger.error("aiohttp not installed. Install with: pip install reconprobe[webhooks]")
        return False
    color = 0x00FF00 if summary.total_vulns == 0 else 0xFFA500 if summary.total_vulns < 5 else 0xFF0000

    embed = {
        "title": f"🛡️ ReconProbe Scan: {summary.domain}",
        "color": color,
        "fields": [
            {"name": "Subdomains", "value": str(summary.total_subdomains), "inline": True},
            {"name": "Open Ports", "value": str(summary.total_open_ports), "inline": True},
            {"name": "Vulnerabilities", "value": str(summary.total_vulns), "inline": True},
            {"name": "Loot Items", "value": str(summary.total_loot_items), "inline": True},
            {"name": "OSINT Findings", "value": str(summary.total_osint_findings), "inline": True},
        ],
        "footer": {"text": f"Scan ID: {summary.scan_id or 'N/A'}  |  Duration: {summary.scan_duration_seconds:.1f}s"},
        "timestamp": summary.timestamp or "",
    }

    payload: dict = {
        "username": config.username,
        "embeds": [embed],
    }
    if config.avatar_url:
        payload["avatar_url"] = config.avatar_url

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(config.webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status in (200, 204):
                    logger.info("Discord notification sent for %s", summary.domain)
                    return True
                body = await resp.text()
                logger.warning("Discord webhook returned %d: %s", resp.status, body[:200])
                return False
    except (asyncio.TimeoutError, aiohttp.ClientError) as e:
        logger.error("Discord webhook error: %s", e)
        return False


async def send_email(
    summary: ScanResultSummary,
    config: EmailConfig,
) -> bool:
    """Send a scan summary email via SMTP."""
    subject = f"ReconProbe Scan Complete: {summary.domain}"

    body_lines = [
        f"ReconProbe Scan Summary — {summary.domain}",
        "=" * 50,
        "",
        f"  Scan ID:       {summary.scan_id or 'N/A'}",
        f"  Timestamp:     {summary.timestamp or 'N/A'}",
        f"  Duration:      {summary.scan_duration_seconds:.1f}s",
        "",
        "--- Findings ---",
        f"  Subdomains:        {summary.total_subdomains}",
        f"  Open Ports:        {summary.total_open_ports}",
        f"  Vulnerabilities:   {summary.total_vulns}",
        f"  Loot Items:        {summary.total_loot_items}",
        f"  OSINT Findings:    {summary.total_osint_findings}",
        "",
        "--- End of Summary ---",
    ]

    if summary.extra:
        body_lines.append("")
        body_lines.append("Extra Data:")
        for key, val in summary.extra.items():
            body_lines.append(f"  {key}: {val}")

    msg = EmailMessage()
    msg.set_content("\n".join(body_lines))
    msg["Subject"] = subject
    msg["From"] = config.from_addr
    msg["To"] = ", ".join(config.to_addrs)

    try:
        loop = asyncio.get_running_loop()

        def _send() -> None:
            with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=30) as server:
                if config.use_tls:
                    server.starttls()
                if config.smtp_user:
                    server.login(config.smtp_user, config.smtp_password)
                server.send_message(msg)

        await loop.run_in_executor(None, _send)
        logger.info("Email notification sent for %s to %s", summary.domain, config.to_addrs)
        return True
    except smtplib.SMTPException as e:
        logger.error("SMTP error sending email: %s", e)
        return False
    except (ConnectionRefusedError, TimeoutError, OSError) as e:
        logger.error("Connection error sending email: %s", e)
        return False


# ── High-level dispatcher ───────────────────────────────────────────────────

@dataclass
class WebhookConfig:
    """Aggregate webhook configuration."""
    slack: Optional[SlackConfig] = None
    discord: Optional[DiscordConfig] = None
    email: Optional[EmailConfig] = None


async def dispatch_webhooks(
    summary: ScanResultSummary,
    config: WebhookConfig,
) -> dict[str, bool]:
    """Dispatch a scan summary to all configured webhook targets.

    Returns a dict mapping target name → success (bool).
    """
    tasks: dict[str, asyncio.Task[bool]] = {}

    if config.slack:
        tasks["slack"] = asyncio.create_task(
            send_slack(summary, config.slack),
        )
    if config.discord:
        tasks["discord"] = asyncio.create_task(
            send_discord(summary, config.discord),
        )
    if config.email:
        tasks["email"] = asyncio.create_task(
            send_email(summary, config.email),
        )

    results: dict[str, bool] = {}
    for name, task in tasks.items():
        try:
            results[name] = await task
        except Exception as e:
            logger.exception("Unhandled error in %s webhook", name)
            results[name] = False
    return results


def build_summary_from_report(report: dict) -> ScanResultSummary:
    """Build a ``ScanResultSummary`` from a full scan report dict."""
    import hashlib
    domain = report.get("target", {}).get("domain", report.get("domain", "unknown"))
    scan_info = report.get("scan_info", {})

    total_ports = 0
    for host, host_data in report.get("port_scan", {}).get("results", {}).items():
        total_ports += len(host_data.get("open_ports", host_data.get("ports", [])))

    vulns = report.get("vulnerability_scan", {}).get("total_cves", 0)
    loot = report.get("loot", {}).get("total_count", 0)
    osint = report.get("osint", {}).get("total_findings", 0)

    scan_id = hashlib.md5(f"{domain}:{scan_info.get('start_time', '')}".encode()).hexdigest()[:12]

    return ScanResultSummary(
        domain=domain,
        total_subdomains=report.get("subdomain_enumeration", {}).get("total_found", 0),
        total_open_ports=total_ports,
        total_vulns=vulns,
        total_loot_items=loot,
        total_osint_findings=osint,
        scan_duration_seconds=scan_info.get("duration_seconds", 0),
        timestamp=scan_info.get("end_time", ""),
        scan_id=scan_id,
    )
