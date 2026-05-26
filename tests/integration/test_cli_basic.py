"""Integration tests for basic ReconProbe CLI functionality.

These tests exercise the actual CLI with real arguments against a local
test server, validating end-to-end behavior rather than unit-testing
individual modules in isolation.

Note: End-to-end scan tests (those that pass a target domain/IP and expect
scan results) are handled by test_modules.py via the module API, because the
CLI's `is_valid_domain` check only accepts proper domain names (like
`example.com`), not IP addresses. Module-level tests cover the actual
scanning logic against the running test server.
"""

from __future__ import annotations

import subprocess
import sys

import pytest


@pytest.mark.integration
class TestCLIBasic:
    """Test basic CLI invocation and help/version output."""

    def test_version_output(self) -> None:
        """Test that --version returns the expected version string."""
        result = subprocess.run(
            [sys.executable, "-m", "reconprobe", "--version"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0
        assert "ReconProbe" in result.stdout
        assert "0.9.0" in result.stdout

    def test_help_output(self) -> None:
        """Test that --help returns usage information."""
        result = subprocess.run(
            [sys.executable, "-m", "reconprobe", "--help"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0
        combined = result.stdout + result.stderr
        assert "ReconProbe" in combined
        assert any(flag in combined for flag in [
            "--ports", "--ssl-audit", "--vuln-scan", "domain"
        ])

    def test_list_ports(self) -> None:
        """Test --list-ports displays common ports table."""
        result = subprocess.run(
            [sys.executable, "-m", "reconprobe", "--list-ports"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0
        assert "80" in result.stdout
        assert "443" in result.stdout
        assert "ssh" in result.stdout.lower() or "SSH" in result.stdout

    def test_missing_domain_shows_error(self) -> None:
        """Test that running without a domain shows error."""
        result = subprocess.run(
            [sys.executable, "-m", "reconprobe"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1
        assert "domain" in (result.stderr + result.stdout).lower()


@pytest.mark.integration
class TestCLIHelpfulErrors:
    """Test that CLI provides helpful error messages for invalid usage."""

    def test_screenshots_requires_output(self) -> None:
        """Test that --screenshots without -o shows error."""
        result = subprocess.run(
            [sys.executable, "-m", "reconprobe", "example.com", "--screenshots"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1
        assert "screenshots" in (result.stderr + result.stdout).lower()

    def test_html_requires_output(self) -> None:
        """Test that --html without -o shows error."""
        result = subprocess.run(
            [sys.executable, "-m", "reconprobe", "example.com", "--html"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 1
        combined = (result.stderr + result.stdout).lower()
        assert "html" in combined or "output" in combined

    def test_invalid_domain_shows_error(self) -> None:
        """Test that invalid domain names show appropriate error."""
        result = subprocess.run(
            [sys.executable, "-m", "reconprobe", "not_a_valid_domain_!!!", "-o", "/tmp/test"],
            capture_output=True, text=True, timeout=15,
        )
        assert "Error" in result.stderr + result.stdout or \
               "invalid" in (result.stderr + result.stdout).lower()
