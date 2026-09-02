"""
Celery Background Worker
========================
Provides asynchronous background scanning for large codebases and container images.
Falls back gracefully if Redis/Celery is unavailable in local development.
"""
import os
import sys
from pathlib import Path

from celery import Celery

# Ensure app package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "quantumshield_worker",
    broker=settings.redis_uri,
    backend=settings.redis_uri,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour maximum
)


@celery_app.task(name="app.worker.run_scan_task", bind=True)
def run_scan_task(self, target_path: str, target_name: str, scan_id: str, threat_horizon: float = 10.0):
    """
    Background worker task to execute full scan asynchronously.
    Updates task state to PROGRESS, SUCCESS, or FAILURE.
    """
    from app.scanners.orchestrator import run_full_scan
    from app.analysis.mosca import MoscaConfig
    from app.api.routes import _summarize, _SCANS

    self.update_state(state="RUNNING", meta={"status": "Scanning codebase...", "scan_id": scan_id})

    try:
        mosca_config = MoscaConfig(quantum_threat_horizon_years=threat_horizon)
        findings, files_scanned = run_full_scan(target_path, mosca_config=mosca_config)
        summary = _summarize(findings, files_scanned, target_name)
        summary.scan_id = scan_id
        _SCANS[scan_id] = summary

        return {
            "status": "COMPLETED",
            "scan_id": scan_id,
            "total_findings": summary.total_findings,
            "overall_health": summary.scores.overall_health,
        }
    except Exception as e:
        self.update_state(state="FAILURE", meta={"error": str(e), "scan_id": scan_id})
        raise
