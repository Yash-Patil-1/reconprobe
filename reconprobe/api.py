"""FastAPI-based REST API server for remote ReconProbe scanning.

Provides endpoints to:
  - Submit scan jobs asynchronously
  - Poll job status / results
  - List available scan profiles
  - Health check

Run with::

    reconprobe --serve
    reconprobe --serve --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from contextlib import asynccontextmanager

try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel, Field
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FastAPI = None  # type: ignore[assignment,misc]
    HTTPException = None  # type: ignore[assignment,misc]
    BaseModel = None  # type: ignore[assignment,misc]
    Field = None  # type: ignore[assignment,misc]
    uvicorn = None  # type: ignore[assignment]
    FASTAPI_AVAILABLE = False

logger = logging.getLogger(__name__)


# ── Enums ───────────────────────────────────────────────────────────────────

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ── Pydantic models ─────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """Request body for submitting a new scan job."""
    domain: str = Field(..., description="Target domain to scan")
    ports: Optional[list[int]] = Field(None, description="Port list (e.g. [80,443,8080])")
    flags: dict[str, Any] = Field(default_factory=dict, description="Scan flags (see run_scan kwargs)")


class ScanJob(BaseModel):
    """Represents a scan job in the system."""
    job_id: str
    domain: str
    flags: dict[str, Any] = Field(default_factory=dict)
    status: ScanStatus = ScanStatus.PENDING
    created_at: str = ""
    completed_at: Optional[str] = None
    progress: int = 0
    result: Optional[dict] = None
    error: Optional[str] = None


class ScanJobStatus(BaseModel):
    """Status response for a scan job."""
    job_id: str
    domain: str
    status: ScanStatus
    created_at: str
    completed_at: Optional[str]
    progress: int


class ScanJobResult(BaseModel):
    """Full result response for a completed scan job."""
    job_id: str
    domain: str
    status: ScanStatus
    result: Optional[dict]
    error: Optional[str]


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "ok"
    version: str = ""
    uptime_seconds: float = 0.0
    active_jobs: int = 0
    total_jobs: int = 0


# ── In-memory job store ─────────────────────────────────────────────────────

class JobStore:
    """Simple in-memory job store."""
    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._lock = asyncio.Lock()

    async def create(self, domain: str, flags: dict[str, Any], ports: Optional[list[int]] = None) -> ScanJob:
        job = ScanJob(
            job_id=uuid.uuid4().hex[:12],
            domain=domain,
            status=ScanStatus.PENDING,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        async with self._lock:
            self._jobs[job.job_id] = job
        return job

    async def get(self, job_id: str) -> Optional[ScanJob]:
        async with self._lock:
            return self._jobs.get(job_id)

    async def update(self, job_id: str, **updates: Any) -> Optional[ScanJob]:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            for key, value in updates.items():
                setattr(job, key, value)
            return job

    async def list_jobs(self, limit: int = 50) -> list[ScanJob]:
        async with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)
            return jobs[:limit]

    @property
    async def total(self) -> int:
        async with self._lock:
            return len(self._jobs)

    @property
    async def active_count(self) -> int:
        async with self._lock:
            return sum(1 for j in self._jobs.values() if j.status in (ScanStatus.PENDING, ScanStatus.RUNNING))


# ── Scan worker ─────────────────────────────────────────────────────────────

class ScanWorker:
    """Background worker that executes scan jobs."""
    def __init__(self, store: JobStore, run_scan_fn: Any) -> None:
        self._store = store
        self._run_scan = run_scan_fn
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._worker_task: Optional[asyncio.Task[None]] = None

    def start(self) -> None:
        if self._worker_task is None:
            self._worker_task = asyncio.create_task(self._worker_loop())

    async def _worker_loop(self) -> None:
        while True:
            job_id = await self._queue.get()
            job = await self._store.get(job_id)
            if job is None:
                continue

            await self._store.update(job_id, status=ScanStatus.RUNNING, progress=10)
            try:
                report = await self._run_scan(
                    domain=job.domain,
                    ports=(job.flags or {}).get("ports"),
                    **{k: v for k, v in (job.flags or {}).items() if k != "ports"},
                )
                await self._store.update(
                    job_id,
                    status=ScanStatus.COMPLETED,
                    progress=100,
                    result=report,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                )
            except Exception as e:
                logger.exception("Scan job %s failed", job_id)
                await self._store.update(
                    job_id,
                    status=ScanStatus.FAILED,
                    error=str(e),
                    completed_at=datetime.now(timezone.utc).isoformat(),
                )
            finally:
                self._queue.task_done()

    async def enqueue(self, job_id: str) -> None:
        await self._queue.put(job_id)


# ── App factory ─────────────────────────────────────────────────────────────

_start_time = datetime.now(timezone.utc)


def create_app(
    run_scan_fn: Any,
    version: str = "0.8.0",
) -> FastAPI:
    """Create and configure the FastAPI application."""
    store = JobStore()
    worker = ScanWorker(store, run_scan_fn)

    # ── Lifecycle (lifespan context manager, preferred over deprecated on_event) ──
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        worker.start()
        yield

    app = FastAPI(
        title="ReconProbe API",
        description="REST API for remote reconnaissance scanning",
        version=version,
        lifespan=lifespan,
    )

    # ── Endpoints ────────────────────────────────────────────────────────

    @app.get("/health", response_model=HealthResponse)
    async def health():
        uptime = (datetime.now(timezone.utc) - _start_time).total_seconds()
        return HealthResponse(
            status="ok",
            version=version,
            uptime_seconds=uptime,
            active_jobs=await store.active_count,
            total_jobs=await store.total,
        )

    @app.post("/scan", response_model=ScanJob, status_code=201)
    async def submit_scan(req: ScanRequest) -> ScanJob:
        """Submit a new scan job."""
        job = await store.create(req.domain, req.flags, req.ports)
        await worker.enqueue(job.job_id)
        return job

    @app.get("/scan/{job_id}", response_model=ScanJobStatus)
    async def get_scan_status(job_id: str) -> ScanJobStatus:
        """Get the status of a scan job."""
        job = await store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        return ScanJobStatus(
            job_id=job.job_id,
            domain=job.domain,
            status=job.status,
            created_at=job.created_at,
            completed_at=job.completed_at,
            progress=job.progress,
        )

    @app.get("/scan/{job_id}/result", response_model=ScanJobResult)
    async def get_scan_result(job_id: str) -> ScanJobResult:
        """Get the full result of a completed scan job."""
        job = await store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        return ScanJobResult(
            job_id=job.job_id,
            domain=job.domain,
            status=job.status,
            result=job.result,
            error=job.error,
        )

    @app.get("/jobs", response_model=list[ScanJobStatus])
    async def list_jobs(limit: int = 50):
        """List recent scan jobs."""
        jobs = await store.list_jobs(limit)
        return [
            ScanJobStatus(
                job_id=j.job_id,
                domain=j.domain,
                status=j.status,
                created_at=j.created_at,
                completed_at=j.completed_at,
                progress=j.progress,
            )
            for j in jobs
        ]

    @app.get("/scan/{job_id}/cancel")
    async def cancel_scan(job_id: str):
        """Cancel a pending scan job."""
        job = await store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.status != ScanStatus.PENDING:
            raise HTTPException(status_code=400, detail="Can only cancel pending jobs")
        await store.update(job_id, status=ScanStatus.FAILED, error="Cancelled by user")
        return {"status": "cancelled", "job_id": job_id}

    return app


# ── Run helper ──────────────────────────────────────────────────────────────

def run_server(
    run_scan_fn: Any,
    host: str = "0.0.0.0",
    port: int = 8000,
    version: str = "0.8.0",
) -> None:
    """Start the FastAPI server synchronously (blocking)."""
    if not FASTAPI_AVAILABLE:
        raise RuntimeError(
            "FastAPI + uvicorn are required for server mode. "
            "Install with: pip install reconprobe[api]"
        )
    app = create_app(run_scan_fn, version=version)
    logger.info("Starting ReconProbe API server on %s:%s", host, port)
    uvicorn.run(app, host=host, port=port, log_level="info")
