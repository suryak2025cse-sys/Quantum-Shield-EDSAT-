"""
PQC / Hybrid Migration Validator
===================================
Evaluates quantum-vulnerable findings against NIST FIPS 203/204/205 standards,
estimating migration effort, latency impact, cost, and library/hardware compatibility.

Status:
  VALID               — fully standardized, active library support available
  PARTIALLY_SUPPORTED — standard finalized, library/ecosystem support still maturing
  BLOCKED             — hard dependencies (HSM firmware, unreleased RFCs, binary-only)
  NOT_APPLICABLE      — classical weakness or secret (non-PQC remediation)
"""
from __future__ import annotations

from app.models.schemas import (
    Category,
    Finding,
    PQCStatus,
    PQCValidationResult,
)

_RULE_PQC_MAP: dict[str, dict] = {
    "QC-RSA-001": {
        "purpose": "key-exchange / signature",
        "recommended_pqc": "ML-KEM (FIPS 203) for key exchange; ML-DSA (FIPS 204) for signatures",
        "nist_standard": "NIST FIPS 203 (ML-KEM) & FIPS 204 (ML-DSA)",
        "hybrid_option": "X25519 + ML-KEM-768 (Draft IETF TLS 1.3)",
        "status": PQCStatus.PARTIALLY_SUPPORTED,
        "hardware_support_status": "HSM firmware update required for native ML-DSA token signing.",
        "estimated_migration_effort": "Medium (40-80 hours)",
        "estimated_latency_impact": "+5-12ms network handshake overhead (larger public keys)",
        "estimated_cost_range": "$$ (Moderate engineering effort)",
        "migration_phase": "Phase 1: 0-6 months (Harvest-Now priority)",
        "reasons": [
            "ML-KEM (FIPS 203) and ML-DSA (FIPS 204) are finalized NIST standards (Aug 2024).",
            "Python: oqs-python provides ML-KEM bindings; OpenSSL 3.5+ adds native provider.",
            "Java: Bouncy Castle 1.78+ supports ML-KEM/ML-DSA in production.",
            "TLS 1.3 post-quantum hybrid ciphersuites are in active IETF draft deployment.",
        ],
        "library_support": "OpenSSL 3.5+, liboqs, Bouncy Castle 1.78+, Go 1.24+ crypto/mlkem.",
        "blockers": [
            "JWT/JOSE standardized algorithm identifiers for ML-DSA are pending final RFC.",
        ],
    },
    "QC-ECC-001": {
        "purpose": "key-exchange / signature",
        "recommended_pqc": "ML-KEM (FIPS 203) for exchange; ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures",
        "nist_standard": "NIST FIPS 203 / 204 / 205",
        "hybrid_option": "ECDH (P-256) + ML-KEM-768",
        "status": PQCStatus.PARTIALLY_SUPPORTED,
        "hardware_support_status": "Modern HSMs support SLH-DSA; ML-DSA firmware rolling out 2025-2026.",
        "estimated_migration_effort": "Medium (30-60 hours)",
        "estimated_latency_impact": "+3-8ms handshake latency (ciphertext size 1088 bytes)",
        "estimated_cost_range": "$$ (Moderate)",
        "migration_phase": "Phase 1: 0-6 months (Key Exchange) / Phase 2 (Signatures)",
        "reasons": [
            "ECC is vulnerable to Shor's algorithm on smaller quantum registers than RSA-2048.",
            "Hybrid ECDH+ML-KEM provides immediate post-quantum confidentiality with classical fallback.",
        ],
        "library_support": "liboqs, Bouncy Castle 1.78+, rustls, Circl, OpenSSL 3.5+.",
        "blockers": [
            "Client SDKs (mobile/embedded) require updated cryptographic provider libraries.",
        ],
    },
    "QC-DH-001": {
        "purpose": "key-exchange",
        "recommended_pqc": "ML-KEM (FIPS 203) hybrid with X25519",
        "nist_standard": "NIST FIPS 203 (ML-KEM)",
        "hybrid_option": "X25519 + ML-KEM-768",
        "status": PQCStatus.PARTIALLY_SUPPORTED,
        "hardware_support_status": "No special hardware required for ephemeral KEM exchange.",
        "estimated_migration_effort": "Low (16-32 hours)",
        "estimated_latency_impact": "+2-5ms (negligible compute impact)",
        "estimated_cost_range": "$ (Low)",
        "migration_phase": "Phase 1: 0-6 months",
        "reasons": [
            "Classic finite-field DH has zero quantum forward secrecy against harvest attacks.",
            "ML-KEM-768 drop-in replaces DH key exchange in modern transport protocols.",
        ],
        "library_support": "OpenSSL 3.5+, liboqs, Bouncy Castle, Go 1.24+.",
        "blockers": [
            "Legacy TLS 1.2 configurations must be upgraded to TLS 1.3 first.",
        ],
    },
    "CERT-X509-001": {
        "purpose": "identity & certificate signing",
        "recommended_pqc": "Dual-signature X.509 certs (ECDSA + ML-DSA / SLH-DSA)",
        "nist_standard": "NIST FIPS 204 (ML-DSA) & FIPS 205 (SLH-DSA)",
        "hybrid_option": "Composite / Dual-Signature X.509 (ITU-T X.509 v3 extension)",
        "status": PQCStatus.PARTIALLY_SUPPORTED,
        "hardware_support_status": "CA Hardware Security Modules require PQC root signing firmware.",
        "estimated_migration_effort": "High (80-160 hours)",
        "estimated_latency_impact": "+15-30ms certificate chain transmission (larger signature sizes)",
        "estimated_cost_range": "$$$ (Public PKI vendor dependent)",
        "migration_phase": "Phase 3: 18-36 months",
        "reasons": [
            "X.509 certificate chains must maintain backwards compatibility with older operating system trust stores.",
            "Dual-signature certificates allow quantum verification while remaining valid on legacy clients.",
        ],
        "library_support": "Bouncy Castle PKIX 1.78+, OpenSSL 3.5 composite cert branch.",
        "blockers": [
            "Public WebPKI Certificate Authorities are in pilot testing phases for PQC issuance.",
        ],
    },
}

_HSM_REASONS = [
    "Hardware Security Module (HSM) or cloud KMS holds asymmetric keys in hardware.",
    "Migration requires vendor firmware supporting NIST FIPS 203/204 algorithms.",
]
_HSM_BLOCKERS = [
    "Cloud provider (AWS KMS, Azure Key Vault, Google Cloud KMS) PQC general availability schedule.",
    "Hardware security module FIPS 140-3 PQC algorithm validation.",
]


def validate_pqc_migrations(findings: list[Finding]) -> list[PQCValidationResult]:
    """Evaluates migration readiness and metrics for all findings."""
    results: list[PQCValidationResult] = []

    for f in findings:
        rule_kb = _RULE_PQC_MAP.get(f.matched_pattern or "")

        if f.category == Category.HSM_CLOUD_KMS:
            results.append(
                PQCValidationResult(
                    finding_id=f.id,
                    finding_title=f.title,
                    current_algorithm=f.title,
                    purpose="key management",
                    recommended_pqc="Vendor-specific PQC HSM or Cloud KMS PQC key profile",
                    nist_standard="NIST FIPS 203 / 204",
                    hybrid_option="Cloud KMS Dual-Key Wrapping",
                    status=PQCStatus.BLOCKED,
                    reasons=_HSM_REASONS,
                    library_support="Vendor HSM firmware and Cloud KMS roadmap required.",
                    hardware_support_status="HSM FIPS 140-3 firmware upgrade required.",
                    known_blockers=_HSM_BLOCKERS,
                    estimated_migration_effort="High (100-200 hours)",
                    estimated_latency_impact="Vendor hardware dependent",
                    estimated_cost_range="$$$ (Hardware / Cloud license)",
                    migration_phase="Phase 3: 18-36 months",
                    confidence="Knowledge Base Heuristic",
                )
            )
            continue

        if f.category == Category.BINARY_ARTIFACT:
            is_quantum = f.quantum_harvest_now_risk
            results.append(
                PQCValidationResult(
                    finding_id=f.id,
                    finding_title=f.title,
                    current_algorithm=f.title,
                    purpose="compiled binary primitive",
                    recommended_pqc="Rebuild binary against PQC-enabled crypto runtime (OpenSSL 3.5+)" if is_quantum else "Modern approved primitive",
                    nist_standard="NIST FIPS 203 / 204" if is_quantum else None,
                    status=PQCStatus.BLOCKED if is_quantum else PQCStatus.NOT_APPLICABLE,
                    reasons=["Compiled binary artifact detected without source rebuild pipeline context."],
                    known_blockers=["Source code rebuild and relinking required."],
                    estimated_migration_effort="Medium (40-80 hours)",
                    estimated_latency_impact="Compile-time linking dependent",
                    estimated_cost_range="$$ (Moderate)",
                    migration_phase="Phase 2: 6-18 months",
                    confidence="Inferred Heuristic",
                )
            )
            continue

        if f.category not in (Category.QUANTUM_VULNERABLE_CRYPTO, Category.CERTIFICATE_ISSUE, Category.CRYPTO_LIBRARY):
            results.append(
                PQCValidationResult(
                    finding_id=f.id,
                    finding_title=f.title,
                    current_algorithm=f.title,
                    purpose="classical security baseline",
                    recommended_pqc=None,
                    status=PQCStatus.NOT_APPLICABLE,
                    reasons=["Classical vulnerability or secret - fix using classical standards (AES-256-GCM, SHA-256, Secret Manager)."],
                    estimated_migration_effort="Low (4-16 hours)",
                    estimated_latency_impact="None",
                    estimated_cost_range="$ (Minimal)",
                    migration_phase="Immediate (Phase 1)",
                    confidence="Detected Evidence",
                )
            )
            continue

        if rule_kb:
            results.append(
                PQCValidationResult(
                    finding_id=f.id,
                    finding_title=f.title,
                    current_algorithm=f.title,
                    purpose=rule_kb["purpose"],
                    recommended_pqc=rule_kb["recommended_pqc"],
                    nist_standard=rule_kb.get("nist_standard"),
                    hybrid_option=rule_kb.get("hybrid_option"),
                    status=rule_kb["status"],
                    reasons=rule_kb["reasons"],
                    library_support=rule_kb["library_support"],
                    hardware_support_status=rule_kb.get("hardware_support_status"),
                    known_blockers=rule_kb.get("blockers", []),
                    estimated_migration_effort=rule_kb.get("estimated_migration_effort"),
                    estimated_latency_impact=rule_kb.get("estimated_latency_impact"),
                    estimated_cost_range=rule_kb.get("estimated_cost_range"),
                    migration_phase=rule_kb.get("migration_phase"),
                    confidence="Detected Evidence",
                )
            )
        else:
            results.append(
                PQCValidationResult(
                    finding_id=f.id,
                    finding_title=f.title,
                    current_algorithm=f.title,
                    purpose="cryptographic primitive",
                    recommended_pqc=f.nist_pqc_recommendation or "NIST FIPS 203/204 standard",
                    nist_standard="NIST PQC Standards (Aug 2024)",
                    status=PQCStatus.PARTIALLY_SUPPORTED,
                    reasons=["Quantum-vulnerable primitive identified.", f"NIST Recommendation: {f.nist_pqc_recommendation or 'ML-KEM / ML-DSA'}."],
                    library_support="Check language-specific PQC bindings.",
                    known_blockers=["Verify protocol and library compatibility."],
                    estimated_migration_effort="Medium (30-60 hours)",
                    estimated_latency_impact="+5-10ms overhead",
                    estimated_cost_range="$$ (Moderate)",
                    migration_phase="Phase 2: 6-18 months",
                    confidence="Knowledge Base Heuristic",
                )
            )

    return results
