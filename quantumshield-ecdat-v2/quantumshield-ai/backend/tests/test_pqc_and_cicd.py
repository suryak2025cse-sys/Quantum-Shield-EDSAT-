"""
Test suite for PQC Validator, Remediation Plan, Tickets, and CI/CD Scanner
"""
from app.analysis.pqc_validator import validate_pqc_migrations
from app.analysis.remediation import build_remediation_plan
from app.analysis.tickets import generate_tickets
from app.cicd.cicd_scanner import run_cicd_scan
from app.models.schemas import (
    ArtifactType,
    Category,
    Criticality,
    Finding,
    PQCStatus,
    Severity,
)


def _make_finding(id_str, category, pattern="QC-RSA-001"):
    return Finding(
        id=id_str,
        severity=Severity.CRITICAL,
        criticality=Criticality.HIGH,
        category=category,
        artifact_type=ArtifactType.ALGORITHM,
        title=f"Critical {id_str}",
        description="Vulnerability description",
        file_path="src/crypto.py",
        matched_pattern=pattern,
    )


def test_pqc_validator_rsa():
    f = _make_finding("f1", Category.QUANTUM_VULNERABLE_CRYPTO, "QC-RSA-001")
    vals = validate_pqc_migrations([f])
    assert len(vals) == 1
    assert vals[0].status == PQCStatus.PARTIALLY_SUPPORTED
    assert "ML-KEM" in (vals[0].recommended_pqc or "")


def test_pqc_validator_hsm():
    f = _make_finding("f2", Category.HSM_CLOUD_KMS)
    vals = validate_pqc_migrations([f])
    assert vals[0].status == PQCStatus.BLOCKED


def test_remediation_plan():
    f1 = _make_finding("f1", Category.QUANTUM_VULNERABLE_CRYPTO)
    f2 = _make_finding("f2", Category.CLASSICAL_CRYPTO_WEAKNESS)
    f2.severity = Severity.LOW

    vals = validate_pqc_migrations([f1, f2])
    plan = build_remediation_plan([f1, f2], [], vals)
    assert len(plan.phases) == 3
    assert plan.total_findings_addressed == 2


def test_ticket_generation():
    f1 = _make_finding("f1", Category.QUANTUM_VULNERABLE_CRYPTO)
    tickets = generate_tickets([f1], [], [])
    assert len(tickets) == 1
    assert tickets[0].priority.value == "critical"
    assert "src/crypto.py" in tickets[0].affected_assets


def test_cicd_scanner(tmp_path):
    # Create dummy source file with weak crypto pattern
    src_file = tmp_path / "test.py"
    src_file.write_text("import md5\n")

    results, should_fail = run_cicd_scan(str(tmp_path))
    assert isinstance(results, list)
    assert isinstance(should_fail, bool)
