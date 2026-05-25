"""Checkpoint and resume module for ReconProbe.

Saves scan state after each phase so interrupted scans can be resumed.
Checkpoints are stored as JSON files alongside scan reports.

Current phases (16 total):
1.   Subdomain Enumeration
2.   Port Scanning
3.   HTTP Probing
4.   Enrichment (Shodan/NVD)
5.   Crawling
6.   Directory Brute-Force
7.   Screenshots
8.   Reporting
9.   Vulnerability Scan (Phase 3)
10.  SSL/TLS Audit (Phase 3)
11.  Subdomain Takeover Detection (Phase 3)
12.  WAF Detection (Phase 3)
13.  Exploit Suggestion (Phase 4)
14.  Payload Generation (Phase 4)
15.  Loot Collection (Phase 4)
16.  MSF Resource Script Generation (Phase 4)
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


class ScanCheckpoint:
    """Manages scan checkpointing for resume support."""

    def __init__(self, domain: str, output_dir: Path):
        self.domain = domain
        self.output_dir = Path(output_dir)
        self._checkpoint_path = self.output_dir / f".checkpoint_{domain.replace('.', '_')}.json"

    def save(
        self,
        phase: int,
        total_phases: int,
        phase_name: str,
        data: Optional[dict] = None,
        completed_phases: Optional[list[int]] = None,
    ) -> None:
        """Save scan checkpoint to disk.

        Args:
            phase: Current phase number (1-indexed).
            total_phases: Total number of phases.
            phase_name: Human-readable phase name.
            data: Optional phase-specific data to persist.
            completed_phases: List of completed phase numbers.
        """
        checkpoint: dict[str, Any] = {
            "domain": self.domain,
            "version": "0.7.0",
            "timestamp": datetime.now().isoformat(),
            "phase": phase,
            "total_phases": total_phases,
            "phase_name": phase_name,
            "completed_phases": sorted(completed_phases or list(range(1, phase + 1))),
            "data": data or {},
        }
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._checkpoint_path.write_text(json.dumps(checkpoint, indent=2, default=str))

    def load(self) -> Optional[dict]:
        """Load checkpoint from disk if it exists.

        Returns:
            Checkpoint dict if available, None otherwise.
        """
        if not self._checkpoint_path.exists():
            return None
        try:
            return json.loads(self._checkpoint_path.read_text())
        except (json.JSONDecodeError, OSError):
            return None

    def get_completed_phases(self) -> list[int]:
        """Get list of completed phase numbers from checkpoint."""
        cp = self.load()
        if cp:
            return cp.get("completed_phases", [])
        return []

    def is_phase_completed(self, phase: int) -> bool:
        """Check if a specific phase was completed in a previous run."""
        return phase in self.get_completed_phases()

    def get_phase_data(self, phase: int) -> Optional[dict]:
        """Get saved data for a specific phase."""
        cp = self.load()
        if cp and cp.get("data"):
            return cp["data"].get(f"phase_{phase}")
        return None

    def clear(self) -> None:
        """Remove checkpoint file."""
        if self._checkpoint_path.exists():
            self._checkpoint_path.unlink()

    @property
    def exists(self) -> bool:
        return self._checkpoint_path.exists()

    def __str__(self) -> str:
        cp = self.load()
        if not cp:
            return "No checkpoint found"
        phase = cp.get("phase", 0)
        total = cp.get("total_phases", 0)
        completed = cp.get("completed_phases", [])
        return (
            f"Checkpoint: phase {phase}/{total} "
            f"({cp.get('phase_name', 'unknown')}), "
            f"{len(completed)} phases completed"
        )
