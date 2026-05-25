"""Tests for reconprobe.api — FastAPI REST server."""

from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport

from reconprobe.api import create_app


@pytest.fixture
def api_app():
    async def fake_run_scan(**kwargs):
        return {
            "domain": kwargs.get("domain", "unknown"),
            "target": {"domain": kwargs.get("domain", "unknown")},
            "subdomain_enumeration": {"total_found": 10},
            "port_scan": {"results": {}},
            "vulnerability_scan": {"total_cves": 0},
            "loot": {"total_count": 0},
            "osint": {"total_findings": 0},
            "scan_info": {"duration_seconds": 5.0, "end_time": "2025-01-15T10:00:00"},
        }
    return create_app(fake_run_scan)


@pytest.mark.asyncio
async def test_health(api_app):
    transport = ASGITransport(app=api_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "active_jobs" in data


@pytest.mark.asyncio
async def test_submit_scan(api_app):
    transport = ASGITransport(app=api_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post("/scan", json={"domain": "example.com"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["domain"] == "example.com"
    assert data["status"] == "pending"
    assert "job_id" in data


@pytest.mark.asyncio
async def test_submit_scan_with_flags(api_app):
    transport = ASGITransport(app=api_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post("/scan", json={
            "domain": "test.com",
            "ports": [80, 443],
            "flags": {"vuln_scan": True, "ssl_audit": True},
        })
    assert resp.status_code == 201
    data = resp.json()
    assert data["domain"] == "test.com"


@pytest.mark.asyncio
async def test_get_scan_status_pending(api_app):
    transport = ASGITransport(app=api_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        create_resp = await ac.post("/scan", json={"domain": "pending.com"})
    job_id = create_resp.json()["job_id"]

    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(f"/scan/{job_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["job_id"] == job_id


@pytest.mark.asyncio
async def test_get_scan_status_not_found(api_app):
    transport = ASGITransport(app=api_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/scan/nonexistent")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_scan_result_not_found(api_app):
    transport = ASGITransport(app=api_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/scan/nonexistent/result")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_scan_result(api_app):
    transport = ASGITransport(app=api_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        create_resp = await ac.post("/scan", json={"domain": "result.com"})
    job_id = create_resp.json()["job_id"]

    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(f"/scan/{job_id}/result")
    assert resp.status_code == 200
    data = resp.json()
    assert data["job_id"] == job_id


@pytest.mark.asyncio
async def test_list_jobs(api_app):
    transport = ASGITransport(app=api_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        await ac.post("/scan", json={"domain": "a.com"})
        await ac.post("/scan", json={"domain": "b.com"})
        resp = await ac.get("/jobs")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 2


@pytest.mark.asyncio
async def test_list_jobs_limit(api_app):
    transport = ASGITransport(app=api_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        for i in range(5):
            await ac.post("/scan", json={"domain": f"limit{i}.com"})
        resp = await ac.get("/jobs?limit=3")
    data = resp.json()
    assert len(data) <= 3


@pytest.mark.asyncio
async def test_cancel_pending_job(api_app):
    transport = ASGITransport(app=api_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        create_resp = await ac.post("/scan", json={"domain": "cancel.com"})
    job_id = create_resp.json()["job_id"]

    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(f"/scan/{job_id}/cancel")
    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelled"


@pytest.mark.asyncio
async def test_cancel_nonexistent_job(api_app):
    transport = ASGITransport(app=api_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/scan/nonexistent/cancel")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_submit_and_get_status(api_app):
    """Submit a scan and verify we can check its status (worker needs uvicorn to start)."""
    transport = ASGITransport(app=api_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post("/scan", json={"domain": "quick.com"})
    job_id = resp.json()["job_id"]

    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(f"/scan/{job_id}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending"
