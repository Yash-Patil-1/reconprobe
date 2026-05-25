"""Shared fixtures and configuration for ReconProbe integration tests."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Iterator, Optional

import pytest

from .test_server import IntegrationTestServer, get_default_config


@pytest.fixture(scope="session")
def test_server() -> Iterator[IntegrationTestServer]:
    """Start a test server for the entire test session.

    The server runs on random ports and provides HTTP + HTTPS endpoints
    for integration testing.
    """
    config = get_default_config()
    server = IntegrationTestServer(config=config)
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def temp_output_dir() -> Iterator[Path]:
    """Create a temporary output directory for test reports."""
    with tempfile.TemporaryDirectory(prefix="reconprobe_inttest_") as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def http_target(test_server: IntegrationTestServer) -> tuple[str, int]:
    """Provide the HTTP target (host, port) for integration tests."""
    return ("127.0.0.1", test_server.http_port)


@pytest.fixture
def https_target(test_server: IntegrationTestServer) -> Optional[tuple[str, int]]:
    """Provide the HTTPS target for SSL/TLS tests, or None if unavailable."""
    if test_server.https_port:
        return ("127.0.0.1", test_server.https_port)
    return None


@pytest.fixture
def http_url(test_server: IntegrationTestServer) -> str:
    """Get base HTTP URL for the test server."""
    return f"http://127.0.0.1:{test_server.http_port}"


@pytest.fixture
def https_url(test_server: IntegrationTestServer) -> Optional[str]:
    """Get base HTTPS URL for the test server, or None."""
    if test_server.https_port:
        return f"https://127.0.0.1:{test_server.https_port}"
    return None
