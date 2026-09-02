"""
API Routes
===========
REST surface for the scanning lifecycle. Scans run async via a background
task (Celery in production — see docker-compose.yml — represented here with
FastAPI BackgroundTasks for a runnable single-process demo).
"""
from __future__ import annotations

import shutil
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.ai.advisor import chat_with_advisor, explain_finding, generate_migration_roadmap
from app.analysis.agility import compute_agility_score
from app.analysis.blast_radius import compute_blast_radii
from app.analysis.classification import ClassificationConfig
from app.analysis.dependency_graph import build_crypto_dependency_graph
from app.analysis.mosca import MoscaConfig
from app.analysis.pqc_validator import validate_pqc_migrations
from app.analysis.related_findings import find_related_findings, DISCLAIMER_TEXT
from app.analysis.remediation import build_remediation_plan
from app.analysis.tickets import generate_tickets, ticket_to_dict, ticket_to_markdown
from app.cbom.cyclonedx_export import generate_cbom
from app.cicd.cicd_scanner import DEFAULT_POLICY, run_cicd_scan
from app.models.schemas import (
    MetricDelta,
    RelatedFinding,
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

# In-memory store for the demo. Production uses MongoDB via Motor (see
# app/core/db.py in the full build) — kept in-process here so the API is
# runnable standalone without infra dependencies.
_SCANS: dict[str, ScanSummary] = {}


class ScanRequest(BaseModel):
    target_name: str
    repo_url: str | None = None


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
    return ScanSummary(
        scan_id=str(uuid.uuid4()),
        target_name=target_name,
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
    )


@router.post("/scans/upload", response_model=ScanSummary)
async def upload_and_scan(
    file: UploadFile,
    target_name: str = "uploaded-project",
    quantum_threat_horizon_years: float = 10.0,
    classification_config: UploadFile | None = None,
):
    """
    Accepts either:
      - a .zip of a source checkout (source code, certs, dependency manifests,
        Dockerfiles/k8s manifests, and compiled binaries are all scanned)
      - a .tar produced by `docker save`, for full container image scanning

    Runs the complete scanner suite (crypto/secrets, certificates,
    dependencies, HSM/cloud KMS, binaries) plus criticality/exposure/Mosca
    classification on every finding.

    Optionally accepts a `classification_config` JSON file (see
    app/analysis/classification.py for the format) to override the default
    business-criticality heuristics with an organization's real asset map.
    """
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
            raise HTTPException(400, f"Invalid classification_config file: {e}")

    with tempfile.TemporaryDirectory() as tmp:
        upload_path = Path(tmp) / file.filename
        upload_path.write_bytes(await file.read())

        if file.filename.endswith(".tar"):
            def _run(directory: str):
                return run_full_scan(directory, class_config, mosca_config)

            try:
                findings, files_scanned, layer_count = scan_container_image(str(upload_path), _run)
            except ValueError as e:
                raise HTTPException(400, str(e))
        else:
            extract_dir = Path(tmp) / "extracted"
            shutil.unpack_archive(str(upload_path), str(extract_dir))
            findings, files_scanned = run_full_scan(str(extract_dir), class_config, mosca_config)

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
    """Exports the scan's findings as a CycloneDX 1.6 Cryptographic Bill of
    Materials (CBOM) — a standardized, machine-readable format, not a
    bespoke JSON shape."""
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return generate_cbom(scan)


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
    if grade_change["from"] != grade_change["to"]:
        grade_phrase = f"and change your grade from {grade_change['from']} to {grade_change['to']}"
    else:
        grade_phrase = f"and keep your grade at {grade_change['from']}"

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


@router.get("/scans/{scan_id}/findings/{finding_id}/related")
async def get_related_findings(scan_id: str, finding_id: str):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    finding = next((f for f in scan.findings if f.id == finding_id), None)
    if not finding:
        raise HTTPException(404, "Finding not found")

    related = find_related_findings(finding, scan.findings)
    return {
        "finding_id": finding_id,
        "finding_title": finding.title,
        "related_findings": related,
        "disclaimer": DISCLAIMER_TEXT,
    }

async def explain(scan_id: str, finding_id: str):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    finding = next((f for f in scan.findings if f.id == finding_id), None)
    if not finding:
        raise HTTPException(404, "Finding not found")
    explanation = await explain_finding(finding)
    return {"finding_id": finding_id, "explanation": explanation}


@router.get("/scans/{scan_id}/roadmap")
async def roadmap(scan_id: str):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    text = await generate_migration_roadmap(scan.findings)
    return {"scan_id": scan_id, "roadmap": text}


@router.post("/copilot/chat")
async def copilot_chat(req: ChatRequest):
    scan = _SCANS.get(req.scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    context = {
        "target_name": scan.target_name,
        "scores": scan.scores.model_dump(),
        "total_findings": scan.total_findings,
        "findings_by_severity": scan.findings_by_severity,
        "findings_by_category": scan.findings_by_category,
        "top_findings": [f.model_dump() for f in scan.findings[:15]],
    }
    answer = await chat_with_advisor(req.question, context)
    return {"answer": answer}


@router.get("/scans/{scan_id}/reports/executive")
async def report_executive(scan_id: str):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {"scan_id": scan_id, "format": "markdown", "content": generate_executive_report(scan)}


@router.get("/scans/{scan_id}/reports/technical")
async def report_technical(scan_id: str):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {"scan_id": scan_id, "format": "markdown", "content": generate_technical_report(scan)}


@router.get("/scans/{scan_id}/reports/migration-checklist")
async def report_migration_checklist(scan_id: str):
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {"scan_id": scan_id, "format": "markdown", "content": generate_migration_checklist(scan)}


# ==========================================================================
# v0.2.0 — New analytical endpoints (lazy, cached on ScanSummary)
# ==========================================================================

def _ensure_graph(scan: ScanSummary):
    """Lazily build and cache the dependency graph."""
    if scan.dependency_graph is None:
        scan.dependency_graph = build_crypto_dependency_graph(scan.findings)
    return scan.dependency_graph


def _ensure_agility(scan: ScanSummary):
    if scan.agility is None:
        scan.agility = compute_agility_score(scan.findings)
    return scan.agility


def _ensure_blast_radii(scan: ScanSummary):
    if scan.blast_radii is None:
        graph = _ensure_graph(scan)
        scan.blast_radii = compute_blast_radii(scan.findings, graph)
    return scan.blast_radii


def _ensure_pqc_validations(scan: ScanSummary):
    if scan.pqc_validations is None:
        scan.pqc_validations = validate_pqc_migrations(scan.findings)
    return scan.pqc_validations


def _ensure_remediation(scan: ScanSummary):
    if scan.remediation_plan is None:
        blast = _ensure_blast_radii(scan)
        vals = _ensure_pqc_validations(scan)
        agility = _ensure_agility(scan)
        scan.remediation_plan = build_remediation_plan(scan.findings, blast, vals, agility)
    return scan.remediation_plan


def _ensure_tickets(scan: ScanSummary):
    if scan.tickets is None:
        blast = _ensure_blast_radii(scan)
        vals = _ensure_pqc_validations(scan)
        plan = _ensure_remediation(scan)
        scan.tickets = generate_tickets(scan.findings, blast, vals, plan)
    return scan.tickets


def _ensure_cicd_policy(scan: ScanSummary):
    if scan.cicd_policy_results is None:
        results, _ = run_cicd_scan.__module__ and None, None  # avoid re-scan; use existing findings
        # Apply policy logic directly to already-scanned findings
        from app.cicd.cicd_scanner import apply_policy, CICDAction
        from app.models.schemas import CICDPolicyResult
        policy_results = []
        for f in scan.findings:
            action, rule_desc = apply_policy(f, DEFAULT_POLICY)
            if action == CICDAction.ALLOW:
                continue  # Only surface BLOCK and WARN in the UI
            msg = (
                f"{'BLOCKED' if action == CICDAction.BLOCK else 'WARNING'} by "
                f"policy rule '{rule_desc}': {f.title}"
            )
            policy_results.append(CICDPolicyResult(
                file_path=f.file_path,
                finding_id=f.id,
                finding_title=f.title,
                severity=f.severity.value,
                action=action,
                policy_rule=rule_desc,
                message=msg,
            ))
        scan.cicd_policy_results = policy_results
    return scan.cicd_policy_results


@router.get("/scans/{scan_id}/dependency-graph")
async def scan_dependency_graph(scan_id: str):
    """Returns the crypto dependency graph for the scan (nodes + edges).
    All edges are heuristically inferred from static analysis."""
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _ensure_graph(scan)


@router.get("/scans/{scan_id}/agility")
async def scan_agility(scan_id: str):
    """Returns the crypto-agility difficulty score with per-factor breakdown."""
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _ensure_agility(scan)


@router.get("/scans/{scan_id}/blast-radius")
async def scan_blast_radius(scan_id: str):
    """Returns migration blast radius for each finding: direct + indirect dependencies + rating."""
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _ensure_blast_radii(scan)


@router.get("/scans/{scan_id}/pqc-validation")
async def scan_pqc_validation(scan_id: str):
    """Validates each finding's PQC migration feasibility: VALID / PARTIALLY_SUPPORTED / BLOCKED."""
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _ensure_pqc_validations(scan)


@router.get("/scans/{scan_id}/remediation")
async def scan_remediation(scan_id: str):
    """Returns a dynamically generated 3-phase remediation plan from actual findings."""
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _ensure_remediation(scan)


@router.get("/scans/{scan_id}/tickets")
async def scan_tickets(scan_id: str):
    """Returns structured migration tickets for all CRITICAL/HIGH findings."""
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _ensure_tickets(scan)


@router.post("/scans/{scan_id}/tickets/export")
async def export_tickets(scan_id: str, fmt: str = "json"):
    """Export all migration tickets as JSON (default) or Markdown.
    fmt: 'json' (default) | 'markdown'
    """
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    tickets = _ensure_tickets(scan)
    if fmt == "markdown":
        content = "\n\n---\n\n".join(ticket_to_markdown(t) for t in tickets)
        return {"scan_id": scan_id, "format": "markdown", "content": content}
    return {"scan_id": scan_id, "format": "json", "tickets": [ticket_to_dict(t) for t in tickets]}


@router.get("/scans/{scan_id}/cicd-policy")
async def scan_cicd_policy(scan_id: str):
    """Applies the default CI/CD security gate policy to this scan's findings.
    Returns BLOCK and WARN results; ALLOW results are omitted for brevity."""
    scan = _SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _ensure_cicd_policy(scan)


@router.get("/health")
async def health():
    return {"status": "ok", "service": "quantumshield-ai-backend"}

