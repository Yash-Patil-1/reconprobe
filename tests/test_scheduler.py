"""Tests for reconprobe.scheduler."""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest
import yaml

from reconprobe.scheduler import (
    ScheduleEntry,
    ScheduleConfig,
    load_schedule,
    save_schedule,
    _is_due,
    _build_run_kwargs,
    run_scheduled_scans,
)


def _make_schedule_yaml(entries: list[dict]) -> str:
    return yaml.safe_dump({"schedules": entries}, default_flow_style=False)


class TestLoadSchedule:
    def test_load_valid(self):
        content = _make_schedule_yaml([
            {"name": "nightly", "target": "example.com", "interval_hours": 24},
            {"name": "weekly", "target": "test.org", "interval_hours": 168, "output_dir": "./reports"},
        ])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(content)
            path = f.name

        try:
            config = load_schedule(path)
            assert len(config.schedules) == 2
            assert config.schedules[0].name == "nightly"
            assert config.schedules[0].target == "example.com"
            assert config.schedules[0].interval_hours == 24
            assert config.schedules[1].output_dir == "./reports"
        finally:
            Path(path).unlink()

    def test_load_missing_file(self):
        with pytest.raises(FileNotFoundError):
            load_schedule("/nonexistent/path.yaml")

    def test_load_invalid_yaml(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("not: valid: yaml: [")
            path = f.name
        try:
            with pytest.raises(yaml.YAMLError):
                load_schedule(path)
        finally:
            Path(path).unlink()

    def test_load_missing_schedules_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("foo: bar")
            path = f.name
        try:
            with pytest.raises(ValueError, match="schedules"):
                load_schedule(path)
        finally:
            Path(path).unlink()

    def test_load_skips_invalid_entries(self):
        content = _make_schedule_yaml([
            {"name": "valid", "target": "example.com", "interval_hours": 24},
            {"name": "invalid no target"},
        ])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            config = load_schedule(path)
            assert len(config.schedules) == 1
        finally:
            Path(path).unlink()


class TestSaveSchedule:
    def test_round_trip(self):
        config = ScheduleConfig(schedules=[
            ScheduleEntry(name="test", target="example.com", interval_hours=12, last_run="2025-01-01T00:00:00"),
        ])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            path = f.name

        try:
            save_schedule(config, path)
            loaded = load_schedule(path)
            assert len(loaded.schedules) == 1
            assert loaded.schedules[0].name == "test"
            assert loaded.schedules[0].last_run == "2025-01-01T00:00:00"
        finally:
            Path(path).unlink()


class TestIsDue:
    def test_no_last_run_is_due(self):
        entry = ScheduleEntry(name="t", target="x.com", interval_hours=24)
        assert _is_due(entry, datetime.now(timezone.utc)) is True

    def test_overdue(self):
        past = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        entry = ScheduleEntry(name="t", target="x.com", interval_hours=24, last_run=past)
        assert _is_due(entry, datetime.now(timezone.utc)) is True

    def test_not_due(self):
        recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        entry = ScheduleEntry(name="t", target="x.com", interval_hours=24, last_run=recent)
        assert _is_due(entry, datetime.now(timezone.utc)) is False

    def test_exactly_due(self):
        exact = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        entry = ScheduleEntry(name="t", target="x.com", interval_hours=24, last_run=exact)
        assert _is_due(entry, datetime.now(timezone.utc)) is True


class TestBuildRunKwargs:
    def test_basic_flags(self):
        entry = ScheduleEntry(name="test", target="example.com", interval_hours=24, flags={
            "vuln_scan": True,
            "ssl_audit": True,
            "osint": True,
        })
        kwargs = _build_run_kwargs(entry)
        assert kwargs["domain"] == "example.com"
        assert kwargs["vuln_scan"] is True
        assert kwargs["ssl_audit"] is True
        assert kwargs["osint"] is True
        # Sensible defaults preserved
        assert kwargs["brute_force"] is True
        assert kwargs["enable_http_probe"] is True

    def test_negation_flags(self):
        entry = ScheduleEntry(name="test", target="x.com", interval_hours=24, flags={
            "no_http_probe": True,
            "no_brute_force": True,
        })
        kwargs = _build_run_kwargs(entry)
        assert kwargs["enable_http_probe"] is False
        assert kwargs["brute_force"] is False

    def test_output_dir(self):
        entry = ScheduleEntry(name="test", target="x.com", interval_hours=24, output_dir="./reports/x_com")
        kwargs = _build_run_kwargs(entry)
        from pathlib import Path
        assert kwargs["output_dir"] == Path("./reports/x_com")

    def test_defaults_when_not_set(self):
        entry = ScheduleEntry(name="test", target="x.com", interval_hours=24)
        kwargs = _build_run_kwargs(entry)
        assert kwargs["enable_zone_transfer"] is True
        assert kwargs["enable_permutations"] is True
        assert kwargs["enable_recursive"] is True


@pytest.mark.asyncio
class TestRunScheduledScans:
    async def test_runs_due_scans(self):
        now = datetime.now(timezone.utc)
        past = (now - timedelta(hours=48)).isoformat()
        config = ScheduleConfig(schedules=[
            ScheduleEntry(name="due1", target="one.com", interval_hours=24, last_run=past),
            ScheduleEntry(name="not_due", target="two.com", interval_hours=24, last_run=now.isoformat()),
        ])

        async def fake_run_scan(**kwargs):
            return {"domain": kwargs["domain"], "success": True}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            path = f.name

        try:
            # Write minimal schedule to path
            save_schedule(config, path)
            results = await run_scheduled_scans(config, path, fake_run_scan, now)
            assert len(results) == 1
            assert results[0]["target"] == "one.com"
            assert results[0]["success"] is True
        finally:
            Path(path).unlink()

    async def test_handles_scan_failure(self):
        now = datetime.now(timezone.utc)
        config = ScheduleConfig(schedules=[
            ScheduleEntry(name="fail_scan", target="fail.com", interval_hours=1),
        ])

        async def failing_scan(**kwargs):
            raise RuntimeError("Connection refused")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            path = f.name

        try:
            save_schedule(config, path)
            results = await run_scheduled_scans(config, path, failing_scan, now)
            assert len(results) == 1
            assert results[0]["success"] is False
            assert "Connection refused" in results[0]["error"]
        finally:
            Path(path).unlink()
