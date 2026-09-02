"""
Unit tests for Crypto-Change Impact Simulation & Related Findings
"""
from fastapi.testclient import TestClient

from app.analysis.related_findings import find_related_findings, DISCLAIMER_TEXT
from app.main import app
from app.models.schemas import Category, Finding, ScoreBreakdown, Severity
from app.scoring.engine import compute_scores

client = TestClient(app)


def _make_finding(f_id: str, title: str, category: Category, severity: Severity, file_path: str, pattern: str = None) -> Finding:
    return Finding(
        id=f_id,
        title=title,
        description="Test description",
        category=category,
        severity=severity,
        file_path=file_path,
        matched_pattern=pattern,
    )


def test_find_related_findings():
    f1 = _make_finding("f1", "RSA Key in auth.py", Category.QUANTUM_VULNERABLE_CRYPTO, Severity.HIGH, "src/auth.py", "QC-RSA-2048")
    f2 = _make_finding("f2", "Weak MD5 in auth.py", Category.CLASSICAL_CRYPTO_WEAKNESS, Severity.MEDIUM, "src/auth.py", "MD5-HASH")
    f3 = _make_finding("f3", "RSA cert in tls.py", Category.QUANTUM_VULNERABLE_CRYPTO, Severity.HIGH, "src/tls.py", "QC-RSA-2048")
    f4 = _make_finding("f4", "Secret key in config.py", Category.SECRET, Severity.CRITICAL, "config/secrets.py")

    all_findings = [f1, f2, f3, f4]

    related_f1 = find_related_findings(f1, all_findings)
    related_ids = [r.id for r in related_f1]

    # f2 is in same file, f3 has same algorithm
    assert "f2" in related_ids
    assert "f3" in related_ids
    assert "f4" not in related_ids

    # Check reason strings
    f2_rel = next(r for r in related_f1 if r.id == "f2")
    assert any("Same file" in reason for reason in f2_rel.relationship_reasons)


def test_compute_scores_simulation():
    f1 = _make_finding("f1", "Secret Key", Category.SECRET, Severity.CRITICAL, "src/config.py")
    f2 = _make_finding("f2", "RSA-1024", Category.QUANTUM_VULNERABLE_CRYPTO, Severity.HIGH, "src/crypto.py")
    
    orig_scores = compute_scores([f1, f2])
    sim_scores = compute_scores([f2], previous_overall=orig_scores.overall_health)

    assert sim_scores.overall_health > orig_scores.overall_health
    assert sim_scores.security_score > orig_scores.security_score
