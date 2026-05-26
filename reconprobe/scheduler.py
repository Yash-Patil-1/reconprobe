"""Scheduled scanning — YAML-config-based recurring scans.

Example ``scan_schedule.yaml``:

.. code-block:: yaml

    schedules:
      - name: "Nightly full scan"
        target: "example.com"
        interval_hours: 24
        flags:
          vuln_scan: true
          ssl_audit: true
          takeover: true
          waf_detect: true
          osint: true
          pdf: true
          csv: true
        output_dir: "./reports/example_com"

      - name: "Weekly OSINT"
        target: "example.org"
        interval_hours: 168
        flags:
          osint: true
          no_http_probe: true
          no_brute_force: true
        output_dir: "./reports/example_org"

Run with::

    reconprobe --schedule scan_schedule.yaml
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)


# ── Configuration models ────────────────────────────────────────────────────

@dataclass
class ScheduleEntry:
    """A single scheduled scan configuration."""
    name: str
    target: str
    interval_hours: float
    output_dir: Optional[str] = None
    flags: dict[str, Any] = field(default_factory=dict)
    last_run: Optional[str] = None


@dataclass
class ScheduleConfig:
    """Parsed schedule configuration from YAML."""
    schedules: list[ScheduleEntry] = field(default_factory=list)


def load_schedule(path: str | Path) -> ScheduleConfig:
    """Load and parse a schedule YAML file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Schedule file not found: {path}")

    raw = yaml.safe_load(path.read_text())
    if not raw or "schedules" not in raw:
        raise ValueError("Invalid schedule file: missing top-level 'schedules' key")

    entries = []
    for entry in raw["schedules"]:
        if not isinstance(entry, dict) or "target" not in entry:
            logger.warning("Skipping invalid schedule entry: %s", entry)
            continue
        entries.append(ScheduleEntry(
            name=entry.get("name", f"Scan {entry['target']}"),
            target=entry["target"],
            interval_hours=entry.get("interval_hours", 24),
            output_dir=entry.get("output_dir"),
            flags=entry.get("flags", {}),
            last_run=entry.get("last_run"),
        ))

    return ScheduleConfig(schedules=entries)


def save_schedule(config: ScheduleConfig, path: str | Path) -> None:
    """Persist the schedule config back to YAML (preserves ``last_run``)."""
    path = Path(path)
    raw = {
        "schedules": [
            {
                "name": e.name,
                "target": e.target,
                "interval_hours": e.interval_hours,
                "output_dir": e.output_dir,
                "flags": e.flags,
                "last_run": e.last_run,
            }
            for e in config.schedules
        ],
    }
    path.write_text(yaml.safe_dump(raw, default_flow_style=False, sort_keys=False))


def _is_due(entry: ScheduleEntry, now: datetime) -> bool:
    """Check whether a schedule entry is due to run."""
    if not entry.last_run:
        return True
    try:
        last = datetime.fromisoformat(entry.last_run)
        elapsed = (now - last).total_seconds() / 3600
        return elapsed >= entry.interval_hours
    except (ValueError, TypeError):
        return True


def _build_run_kwargs(entry: ScheduleEntry) -> dict[str, Any]:
    """Build keyword arguments for ``run_scan`` from schedule flags."""
    kwargs: dict[str, Any] = {
        "domain": entry.target,
        "output_dir": Path(entry.output_dir) if entry.output_dir else None,
    }

    # Translate YAML flag keys to run_scan parameter names
    flag_map: dict[str, str] = {
        "no_http_probe": "enable_http_probe",
        "no_brute_force": "brute_force",
        "no_enrichment": "enable_enrichment",
        "no_credential_check": "check_default_creds",
        "no_zone_transfer": "enable_zone_transfer",
        "no_permutations": "enable_permutations",
        "no_recursive": "enable_recursive",
        "no_active_waf": "enable_active_waf",
        "no_github_dork": "enable_github_dork",
        "no_google_dorks": "enable_google_dorks",
        "no_email_harvest": "enable_email_harvest",
        "no_whois": "enable_whois",
        "no_social": "enable_social_footprint",
        "no_breach_check": "enable_breach_check",
        "no_tech_osint": "enable_tech_osint",
    }

    for flag_key, value in entry.flags.items():
        if flag_key in flag_map:
            # Negation flag — inverted logic
            param = flag_map[flag_key]
            kwargs[param] = not value
        else:
            kwargs[flag_key] = value

    # Sensible defaults for flags not set
    kwargs.setdefault("brute_force", True)
    kwargs.setdefault("enable_http_probe", True)
    kwargs.setdefault("enable_enrichment", True)
    kwargs.setdefault("check_default_creds", True)
    kwargs.setdefault("enable_zone_transfer", True)
    kwargs.setdefault("enable_permutations", True)
    kwargs.setdefault("enable_recursive", True)
    kwargs.setdefault("enable_active_waf", True)
    kwargs.setdefault("enable_github_dork", True)
    kwargs.setdefault("enable_google_dorks", True)
    kwargs.setdefault("enable_email_harvest", True)
    kwargs.setdefault("enable_whois", True)
    kwargs.setdefault("enable_social_footprint", True)
    kwargs.setdefault("enable_breach_check", True)
    kwargs.setdefault("enable_tech_osint", True)

    return kwargs


async def run_scheduled_scans(
    config: ScheduleConfig,
    schedule_path: str | Path,
    run_scan_fn: Any,
    now: Optional[datetime] = None,
) -> list[dict]:
    """Run all due scans from a schedule config.

    Parameters
    ----------
    config:
        Parsed schedule configuration.
    schedule_path:
        Path to the schedule file (to persist ``last_run`` timestamps).
    run_scan_fn:
        The ``run_scan`` async function from ``runner.py``.
    now:
        Current time (defaults to ``datetime.now(timezone.utc)``).

    Returns
    -------
    list[dict]
        Results from each scan run.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    results: list[dict] = []
    for entry in config.schedules:
        if not _is_due(entry, now):
            logger.info("Skipping '%s' — not due yet (last run: %s)", entry.name, entry.last_run)
            continue

        logger.info("Running scheduled scan '%s' on %s", entry.name, entry.target)
        kwargs = _build_run_kwargs(entry)

        try:
            report = await run_scan_fn(**kwargs)
            results.append({"name": entry.name, "target": entry.target, "success": True, "report": report})
        except Exception as e:
            logger.exception("Scheduled scan '%s' failed", entry.name)
            results.append({"name": entry.name, "target": entry.target, "success": False, "error": str(e)})

        # Update last_run timestamp and persist
        entry.last_run = now.isoformat()
        try:
            save_schedule(config, schedule_path)
        except OSError:
            logger.warning("Could not save schedule after '%s'", entry.name)

    return results


async def run_scheduler_loop(
    config: ScheduleConfig,
    schedule_path: str | Path,
    run_scan_fn: Any,
    interval_check: float = 60.0,
    run_once: bool = False,
) -> None:
    """Run the scheduler loop, checking for due scans at ``interval_check`` seconds.

    In ``run_once`` mode, executes due scans and returns.
    Otherwise, loops forever checking every ``interval_check`` seconds.
    """
    from rich.console import Console
    console = Console()

    console.print(f"[bold cyan]Scheduler[/bold cyan] — loaded [green]{len(config.schedules)}[/green] schedule(s)")
    for entry in config.schedules:
        last = entry.last_run or "never"
        console.print(f"  • [yellow]{entry.name}[/yellow] → {entry.target} "
                      f"(every {entry.interval_hours}h, last run: {last})")

    console.print("")

    while True:
        now = datetime.now(timezone.utc)
        results = await run_scheduled_scans(config, schedule_path, run_scan_fn, now)

        for r in results:
            if r["success"]:
                console.print(f"  [green]✓[/green] {r['name']} — scan completed successfully")
            else:
                console.print(f"  [red]✗[/red] {r['name']} — {r.get('error', 'unknown error')}")

        if run_once:
            break

        next_check = interval_check
        console.print(f"[dim]Next check in {next_check:.0f}s...[/dim]")
        await asyncio.sleep(next_check)
