"""Integration tests for ReconProbe Docker build.

These tests verify that the Docker image builds successfully and the container
starts correctly, validating the production deployment path.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.integration
@pytest.mark.docker
class TestDockerBuild:
    """Test Docker image builds and runs correctly."""
    
    @pytest.fixture(scope="class")
    def project_root(self) -> Path:
        """Return the project root directory."""
        return Path(__file__).resolve().parent.parent.parent
    
    def test_docker_build(self, project_root: Path) -> None:
        """Test that the Docker image builds successfully."""
        result = subprocess.run(
            ["docker", "build", "-t", "reconprobe:test", "-f", str(project_root / "Dockerfile"), "."],
            capture_output=True, text=True, timeout=300,
            cwd=str(project_root),
        )
        assert result.returncode == 0, (
            f"Docker build failed:\n{result.stderr}\n{result.stdout}"
        )
    
    def test_docker_version(self) -> None:
        """Test that the Docker image runs and shows version correctly."""
        result = subprocess.run(
            ["docker", "run", "--rm", "reconprobe:test", "--version"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        assert "ReconProbe" in result.stdout
        assert "v1.0.0" in result.stdout or "1.0.0" in result.stdout
    
    def test_docker_help(self) -> None:
        """Test that the Docker image provides help output."""
        result = subprocess.run(
            ["docker", "run", "--rm", "reconprobe:test", "--help"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        assert any(flag in result.stdout for flag in [
            "--ports", "--ssl-audit", "--vuln-scan", "--osint"
        ])
    
    def test_docker_list_ports(self) -> None:
        """Test that Docker container runs --list-ports."""
        result = subprocess.run(
            ["docker", "run", "--rm", "reconprobe:test", "--list-ports"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        assert "80" in result.stdout
        assert "443" in result.stdout
