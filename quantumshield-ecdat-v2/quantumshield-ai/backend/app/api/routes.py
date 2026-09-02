"""
API Routes
===========
REST interface for QuantumShield scanning lifecycle, CBOM export, AI advisor,
impact simulation, Git repository scanning, and CI/CD policy gates.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import uuid
import zipfile
import tarfile
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.ai.advisor import chat_with_advisor, explain_finding, generate_migration_roadmap
from app.analysis.agility import compute_agility_score
from app.analysis.asset_inventory import build_normalized_inventory
from app.analysis.blast_radius import compute_blast_radii
from app.analysis.classification import ClassificationConfig
from app.analysis.dependency_graph import build_crypto_dependency_graph
from app.analysis.mosca import MoscaConfig
from app.analysis.pqc_validator import validate_pqc_migrations
from app.analysis.related_findings import find_related_findings, DISCLAIMER_TEXT
from app.analysis.remediation import build_remediation_plan
from app.analysis.tickets import generate_tickets, ticket_to_dict, ticket_to_markdown
from app.cbom.cyclonedx_export import generate_cbom, validate_cbom_structure
from app.cicd.cicd_scanner import DEFAULT_POLICY, run_cicd_scan
from app.models.schemas import (
    MetricDelta,
    RelatedFinding,
    ScanStatus,
    ScanSummary,
    SimulateRequest,
    SimulateResponse,
)
from app.reports.generator import (
    generate_executive_report,
    generate_migration_checklist,
    generate_technical_report,
)
from app.scanners.container_scanner import scan_container_image
from app.scanners.orchestrator import run_full_scan
from app.scoring.engine import compute_scores

router = APIRouter()

# In-memory store for scans (fast and zero-infra requirement for standalone / demo)
_SCANS: dict[str, ScanSummary] = {}

# Safety thresholds for uploads
MAX_UPLOAD_SIZE_BYTES = 250 * 1024 * 1024       # 250 MB archive limit
MAX_EXTRACTED_SIZE_BYTES = 1024 * 1024 * 1024   # 1 GB unpacked limit
MAX_EXTRACTED_FILES = 150000                    # 150,000 files max


class GitScanRequest(BaseModel):
    repo_url: str
    target_name: str | None = None
    branch: str | None = None
    quantum_threat_horizon_years: float = 10.0


class ChatRequest(BaseModel):
    scan_id: str
    question: str


def _summarize(findings: list, files_scanned: int, target_name: str) -> ScanSummary:
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_artifact_type: dict[str, int] = {}
    by_criticality: dict[str, int] = {}
    mosca_at_risk = 0

    for f in findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        by_category[f.category.value] = by_category.get(f.category.value, 0) + 1
        by_artifact_type[f.artifact_type.value] = by_artifact_type.get(f.artifact_type.value, 0) + 1
        if f.criticality:
            by_criticality[f.criticality.value] = by_criticality.get(f.criticality.value, 0) + 1
        if f.mosca and f.mosca.risk_level.value == "at_risk":
            mosca_at_risk += 1

    scores = compute_scores(findings)
    normalized_assets = build_normalized_inventory(findings)

    # Pre-calculate extended v0.2.0 analytical models so dashboard is fully hydrated
    graph = build_crypto_dependency_graph(findings)
    agility = compute_agility_score(findings)
    blast_radii = compute_blast_radii(findings, graph)
    pqc_validations = validate_pqc_migrations(findings)
    remediation_plan = build_remediation_plan(findings, blast_radii, pqc_validations)
    tickets = generate_tickets(findings, blast_radii, pqc_validations)

    return ScanSummary(
        scan_id=str(uuid.uuid4()),
        target_name=target_name,
        status=ScanStatus.COMPLETED,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        files_scanned=files_scanned,
        total_findings=len(findings),
        findings_by_severity=by_severity,
        findings_by_category=by_category,
        findings_by_artifact_type=by_artifact_type,
        findings_by_criticality=by_criticality,
        mosca_at_risk_count=mosca_at_risk,
        scores=scores,
        findings=findings,
        normalized_assets=normalized_assets,
        dependency_graph=graph,
        agility=agility,
        blast_radii=blast_radii,
        pqc_validations=pqc_validations,
        remediation_plan=remediation_plan,
        tickets=tickets,
    )


SKIP_EXTRACT_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build", ".next"}


def _safe_unpack_zip(zip_path: Path, extract_dir: Path):
    """Safely extracts ZIP with path traversal and decompression bomb guards."""
    total_size = 0
    file_count = 0

    with zipfile.ZipFile(zip_path, "r") as zf:
        members = zf.infolist()
        if len(members) > MAX_EXTRACTED_FILES:
            raise HTTPException(400, f"Archive contains too many files ({len(members):,} files, limit: {MAX_EXTRACTED_FILES:,})")

        for member in members:
            # Path traversal check
            dest_path = (extract_dir / member.filename).resolve()
            if not str(dest_path).startswith(str(extract_dir.resolve())):
                raise HTTPException(400, f"Dangerous path traversal detected in archive: {member.filename}")

            # Ignore heavy non-source directories to ensure fast extraction
            parts = Path(member.filename).parts
            if any(p in SKIP_EXTRACT_DIRS for p in parts):
                continue

            file_count += 1
            total_size += member.file_size
            if total_size > MAX_EXTRACTED_SIZE_BYTES:
                raise HTTPException(400, "Extracted source files exceed size limit (1 GB)")

            zf.extract(member, extract_dir)


@router.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "QuantumShield AI API",
        "version": "0.2.0",
        "total_scans_in_memory": len(_SCANS),
        "features": {
            "pqc_migration_validation": True,
            "cbom_cyclonedx_1_6": True,
            "mosca_threat_assessment": True,
            "git_clone_scanning": True,
            "offline_advisor_fallback": True,
        }
    }


@router.post("/scans/upload", response_model=ScanSummary)
async def upload_and_scan(
    file: UploadFile,
    target_name: str = "uploaded-project",
    quantum_threat_horizon_years: float = 10.0,
    classification_config: UploadFile | None = None,
):
    if not (file.filename.endswith(".zip") or file.filename.endswith(".tar")):
        raise HTTPException(400, "Only .zip (source) or .tar (docker save image) uploads are supported")

    mosca_config = MoscaConfig(quantum_threat_horizon_years=quantum_threat_horizon_years)
    class_config = None

    if classification_config is not None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_cfg:
            tmp_cfg.write(await classification_config.read())
            tmp_cfg_path = tmp_cfg.name
        try:
            class_config = ClassificationConfig.from_json_file(tmp_cfg_path)
        except Exception as e:
            raise HTTPException(400, f"Invalid classification_config JSON file: {e}")

    with tempfile.TemporaryDirectory() as tmp:
        upload_path = Path(tmp) / file.filename
        content = await file.read()
        if len(content) > MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(400, f"File size exceeds 100 MB limit (received {len(content) // (1024*1024)} MB)")
        upload_path.write_bytes(content)

        try:
            if file.filename.endswith(".tar"):
                def _run(directory: str):
                    return run_full_scan(directory, class_config, mosca_config, skip_osv_lookup=True)

                findings, files_scanned, layer_count = scan_container_image(str(upload_path), _run)
            else:
                extract_dir = Path(tmp) / "extracted"
                extract_dir.mkdir(parents=True, exist_ok=True)
                _safe_unpack_zip(upload_path, extract_dir)
                findings, files_scanned = run_full_scan(str(extract_dir), class_config, mosca_config, skip_osv_lookup=True)

            summary = _summarize(findings, files_scanned, target_name)
            _SCANS[summary.scan_id] = summary
            return summary
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, f"Scanning execution failed: {str(e)}")


@router.post("/scans/git", response_model=ScanSummary)
async def scan_git_repository(req: GitScanRequest):
    """
    Clones a remote Git repository securely into an isolated temporary folder,
    scans it, and removes the clone immediately. Does not execute code or hooks.
    """
    url = req.repo_url.strip()
    # Basic URL format sanitization
    if not (url.startswith("https://") or url.startswith("http://") or url.startswith("git@")):
        raise HTTPException(400, "Invalid Git repository URL (must start with https://, http://, or git@)")

    target_name = req.target_name or url.rstrip("/").split("/")[-1].replace(".git", "")
    mosca_config = MoscaConfig(quantum_threat_horizon_years=req.quantum_threat_horizon_years)

    with tempfile.TemporaryDirectory() as tmp_dir:
        clone_dest = Path(tmp_dir) / "repo"
        cmd = ["git", "clone", "--depth", "1"]
        if req.branch:
            cmd.extend(["--branch", req.branch])
        cmd.extend([url, str(clone_dest)])

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                env={"GIT_TERMINAL_PROMPT": "0"},  # Do not hang on auth prompt
            )
            if res.returncode != 0:
                raise HTTPException(400, f"Git clone failed: {res.stderr[:200]}")
        except subprocess.TimeoutExpired:
            raise HTTPException(408, "Git clone timed out after 120 seconds")
        except FileNotFoundError:
            raise HTTPException(500, "Git executable not found in server environment")

        findings, files_scanned = run_full_scan(str(clone_dest), mosca_config=mosca_config, skip_osv_lookup=True)
        summary = _summarize(findings, files_scanned, target_name)
        _SCANS[summary.scan_id] = summary
        return summary


@router.get("/scans/{scan_id}", response_model=ScanSummary)
async def get_scan(scan_id: str):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.get("/scans", response_model=list[ScanSummary])
async def list_scans():
    return list(_SCANS.values())


@router.get("/scans/{scan_id}/cbom")
async def scan_cbom(scan_id: str):
    """Exports scan findings as a standardized CycloneDX 1.6 CBOM JSON document."""
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    cbom = generate_cbom(scan)
    valid, errors = validate_cbom_structure(cbom)
    if not valid:
        raise HTTPException(500, f"CBOM validation failed: {errors}")
    return cbom


@router.post("/scans/{scan_id}/simulate", response_model=SimulateResponse)
async def simulate_fix(scan_id: str, req: SimulateRequest):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    resolved_set = set(req.finding_ids)
    remaining_findings = [f for f in scan.findings if f.id not in resolved_set]

    original_scores = scan.scores
    simulated_scores = compute_scores(remaining_findings, previous_overall=original_scores.overall_health)

    metric_deltas = {
        "security_score": MetricDelta(
            original=original_scores.security_score,
            simulated=simulated_scores.security_score,
            delta=round(simulated_scores.security_score - original_scores.security_score, 1),
        ),
        "quantum_readiness_score": MetricDelta(
            original=original_scores.quantum_readiness_score,
            simulated=simulated_scores.quantum_readiness_score,
            delta=round(simulated_scores.quantum_readiness_score - original_scores.quantum_readiness_score, 1),
        ),
        "compliance_score": MetricDelta(
            original=original_scores.compliance_score,
            simulated=simulated_scores.compliance_score,
            delta=round(simulated_scores.compliance_score - original_scores.compliance_score, 1),
        ),
        "overall_health": MetricDelta(
            original=original_scores.overall_health,
            simulated=simulated_scores.overall_health,
            delta=round(simulated_scores.overall_health - original_scores.overall_health, 1),
        ),
    }

    grade_change = {
        "from": original_scores.grade,
        "to": simulated_scores.grade,
    }

    count = len(req.finding_ids)
    grade_phrase = (
        f"and change your grade from {grade_change['from']} to {grade_change['to']}"
        if grade_change["from"] != grade_change["to"]
        else f"and keep your grade at {grade_change['from']}"
    )

    summary_statement = (
        f"Fixing these {count} finding{'s' if count != 1 else ''} would raise Overall Health "
        f"from {original_scores.overall_health} to {simulated_scores.overall_health} {grade_phrase}."
    )

    related_map: dict[str, list[RelatedFinding]] = {}
    for fid in req.finding_ids:
        target_f = next((f for f in scan.findings if f.id == fid), None)
        if target_f:
            related_map[fid] = find_related_findings(target_f, scan.findings)

    return SimulateResponse(
        resolved_finding_ids=req.finding_ids,
        original_scores=original_scores,
        simulated_scores=simulated_scores,
        metric_deltas=metric_deltas,
        grade_change=grade_change,
        summary_statement=summary_statement,
        related_findings=related_map,
        disclaimer=DISCLAIMER_TEXT,
    )


@router.get("/scans/{scan_id}/reports/{report_type}")
async def get_report(scan_id: str, report_type: str):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    rtype = report_type.lower()
    if rtype == "executive":
        content = generate_executive_report(scan)
    elif rtype in ("technical", "technical-findings"):
        content = generate_technical_report(scan)
    elif rtype in ("checklist", "migration-checklist", "migration_checklist"):
        content = generate_migration_checklist(scan)
    else:
        raise HTTPException(400, "Unknown report type (supported: executive, technical, migration-checklist)")

    return {"report_type": report_type, "scan_id": scan_id, "markdown": content, "content": content}


@router.get("/scans/{scan_id}/dependency-graph")
async def get_dependency_graph(scan_id: str):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.dependency_graph:
        return scan.dependency_graph
    return build_crypto_dependency_graph(scan.findings)


@router.get("/scans/{scan_id}/agility")
async def get_agility_score(scan_id: str):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.agility:
        return scan.agility
    return compute_agility_score(scan.findings)


@router.get("/scans/{scan_id}/blast-radius")
async def get_blast_radius(scan_id: str):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.blast_radii:
        return scan.blast_radii
    graph = scan.dependency_graph or build_crypto_dependency_graph(scan.findings)
    return compute_blast_radii(scan.findings, graph)


@router.get("/scans/{scan_id}/pqc-validation")
async def get_pqc_validation(scan_id: str):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.pqc_validations:
        return scan.pqc_validations
    return validate_pqc_migrations(scan.findings)


@router.get("/scans/{scan_id}/remediation")
async def get_remediation_plan(scan_id: str):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.remediation_plan:
        return scan.remediation_plan
    graph = scan.dependency_graph or build_crypto_dependency_graph(scan.findings)
    blast = scan.blast_radii or compute_blast_radii(scan.findings, graph)
    pqc = scan.pqc_validations or validate_pqc_migrations(scan.findings)
    return build_remediation_plan(scan.findings, blast, pqc)


@router.get("/scans/{scan_id}/tickets")
async def get_tickets(scan_id: str):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.tickets:
        return scan.tickets
    graph = scan.dependency_graph or build_crypto_dependency_graph(scan.findings)
    blast = scan.blast_radii or compute_blast_radii(scan.findings, graph)
    pqc = scan.pqc_validations or validate_pqc_migrations(scan.findings)
    return generate_tickets(scan.findings, blast, pqc)


@router.post("/scans/{scan_id}/tickets/export")
async def export_tickets(scan_id: str, fmt: str = "jira"):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    tickets = scan.tickets or generate_tickets(scan.findings, scan.blast_radii or [], scan.pqc_validations or [])
    if fmt == "markdown":
        md = "\n\n---\n\n".join(ticket_to_markdown(t) for t in tickets)
        return {"format": "markdown", "content": md}
    data = [ticket_to_dict(t) for t in tickets]
    return {"format": "jira", "tickets": data}


@router.get("/scans/{scan_id}/cicd-policy")
async def get_cicd_policy(scan_id: str):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {"policy": DEFAULT_POLICY, "findings_count": len(scan.findings)}


@router.get("/scans/{scan_id}/roadmap")
@router.post("/advisor/roadmap")
async def roadmap(scan_id: str):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {"roadmap": await generate_migration_roadmap(scan.findings), "content": await generate_migration_roadmap(scan.findings)}


@router.post("/advisor/explain")
async def explain(finding_id: str, scan_id: str):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    finding = next((f for f in scan.findings if f.id == finding_id), None)
    if not finding:
        raise HTTPException(404, "Finding not found")
    return {"explanation": await explain_finding(finding)}


@router.post("/copilot/chat")
@router.post("/advisor/chat")
async def chat(req: ChatRequest):
    scan = _SCANS.get(req.scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    context = scan.model_dump()
    answer = await chat_with_advisor(req.question, context)
    return {"answer": answer, "reply": answer}
