"""
Test Suite: Normalized Asset Inventory, Mosca Sensitivity, CycloneDX 1.6 CBOM, and Offline AI Fallback
"""
import pytest
from app.analysis.asset_inventory import build_normalized_inventory
from app.analysis.mosca import compute_sensitivity_matrix
from app.cbom.cyclonedx_export import generate_cbom, validate_cbom_structure
from app.ai.advisor import _generate_offline_explanation, _generate_offline_roadmap, _generate_offline_chat
from app.models.schemas import (
    ArtifactType,
    Category,
    Finding,
    ScoreBreakdown,
    ScanSummary,
    Severity,
)


def _make_f(f_id: str, title: str, category: Category, artifact_type: ArtifactType, path: str = "src/crypto.py") -> Finding:
    return Finding(
        id=f_id,
        category=category,
        severity=Severity.HIGH,
        title=title,
        description="Desc",
        file_path=path,
        matched_pattern="QC-RSA-001",
        artifact_type=artifact_type,
        quantum_harvest_now_risk=True,
    )


def test_asset_normalization_deduplication():
    # Two separate findings of RSA in different files should map to unified asset
    f1 = _make_f("f1", "RSA in auth", Category.QUANTUM_VULNERABLE_CRYPTO, ArtifactType.ALGORITHM, "src/auth.py")
    f2 = _make_f("f2", "RSA in crypto", Category.QUANTUM_VULNERABLE_CRYPTO, ArtifactType.ALGORITHM, "src/crypto.py")
    f3 = _make_f("f3", "MD5 in hash", Category.CLASSICAL_CRYPTO_WEAKNESS, ArtifactType.ALGORITHM, "src/hash.py")
    f3.matched_pattern = "CS-MD5-001"

    inventory = build_normalized_inventory([f1, f2, f3])
    assert len(inventory) == 2  # RSA unified, MD5 unified
    rsa_asset = next(a for a in inventory if a.algorithm_or_primitive == "RSA")
    assert rsa_asset.occurrences_count == 2
    assert len(rsa_asset.locations) == 2
    assert "src/auth.py" in rsa_asset.locations
    assert "src/crypto.py" in rsa_asset.locations


def test_mosca_sensitivity_matrix():
    matrix = compute_sensitivity_matrix(x=10.0, y=3.0, horizons=[5.0, 10.0, 14.0, 16.0])
    assert matrix["Z=5y"]["status"] == "AT_RISK"
    assert matrix["Z=10y"]["status"] == "AT_RISK"
    assert matrix["Z=14y"]["status"] == "WATCH"
    assert matrix["Z=16y"]["status"] == "SAFE"


def test_cyclonedx_1_6_cbom_generation():
    f1 = _make_f("f1", "RSA 2048 Key", Category.QUANTUM_VULNERABLE_CRYPTO, ArtifactType.ALGORITHM)
    f2 = _make_f("f2", "pycryptodome", Category.CRYPTO_LIBRARY, ArtifactType.LIBRARY)
    f2.extra = {"library": "pycryptodome", "version": "3.19.0", "ecosystem": "PyPI"}

    scan = ScanSummary(
        scan_id="test-scan-123",
        target_name="TestApp",
        started_at="2026-09-02T12:00:00Z",
        completed_at="2026-09-02T12:01:00Z",
        files_scanned=10,
        total_findings=2,
        findings_by_severity={"high": 2},
        findings_by_category={"quantum_vulnerable_crypto": 1, "crypto_library": 1},
        scores=ScoreBreakdown(
            security_score=70.0,
            quantum_readiness_score=60.0,
            criticality_score=20.0,
            compliance_score=65.0,
            overall_health=68.0,
            risk_trend="stable",
            grade="D",
        ),
        findings=[f1, f2],
    )

    cbom = generate_cbom(scan)
    valid, errors = validate_cbom_structure(cbom)
    assert valid is True
    assert errors == []
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert len(cbom["components"]) == 2
    assert any(c["type"] == "library" for c in cbom["components"])
    assert any(c["type"] == "cryptographic-asset" for c in cbom["components"])


@pytest.mark.asyncio
async def test_offline_ai_advisor_fallback():
    f = _make_f("f1", "RSA key generation", Category.QUANTUM_VULNERABLE_CRYPTO, ArtifactType.ALGORITHM)
    f.nist_pqc_recommendation = "ML-KEM (FIPS 203)"

    exp = _generate_offline_explanation(f)
    assert "Technical Impact" in exp
    assert "Business Impact" in exp
    assert "Shor's algorithm" in exp

    roadmap = _generate_offline_roadmap([f])
    assert "Phase 1" in roadmap
    assert "FIPS 203" in roadmap

    chat_res = _generate_offline_chat("Which finding should I fix first?", {"total_findings": 1, "findings": [f.model_dump()]})
    assert "prioritize" in chat_res.lower() or "recommendation" in chat_res.lower()
