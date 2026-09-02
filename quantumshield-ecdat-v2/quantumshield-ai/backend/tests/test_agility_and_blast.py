"""
Test suite for Crypto-Agility Scorer and Blast Radius
"""
from app.analysis.agility import compute_agility_score
from app.analysis.blast_radius import compute_blast_radii
from app.analysis.dependency_graph import build_crypto_dependency_graph
from app.models.schemas import (
    AgilityLabel,
    ArtifactType,
    BlastRating,
    Category,
    Criticality,
    Finding,
    Severity,
)


def _make_finding(id_str, category, file_path="src/main.py"):
    return Finding(
        id=id_str,
        severity=Severity.HIGH,
        criticality=Criticality.HIGH,
        category=category,
        artifact_type=ArtifactType.ALGORITHM,
        title=f"Finding {id_str}",
        description="Description",
        file_path=file_path,
        matched_pattern="QC-RSA-001",
    )


def test_agility_score_empty():
    score = compute_agility_score([])
    assert score.score == 0.0
    assert score.label == AgilityLabel.EASY


def test_agility_score_with_findings():
    findings = [
        _make_finding("f1", Category.QUANTUM_VULNERABLE_CRYPTO, "src/auth.py"),
        _make_finding("f2", Category.HSM_CLOUD_KMS, "src/kms.py"),
        _make_finding("f3", Category.DEPENDENCY_CVE, "src/deps.py"),
    ]
    score = compute_agility_score(findings)
    assert 0.0 <= score.score <= 100.0
    assert len(score.factors) == 6
    assert score.is_heuristic is True


def test_blast_radius_computation():
    f1 = _make_finding("f1", Category.QUANTUM_VULNERABLE_CRYPTO, "src/auth.py")
    graph = build_crypto_dependency_graph([f1])
    radii = compute_blast_radii([f1], graph)
    assert len(radii) == 1
    assert radii[0].finding_id == "f1"
    assert radii[0].rating in (BlastRating.LOW, BlastRating.MEDIUM, BlastRating.HIGH)
