"""
PQC / Hybrid Migration Validator
===================================
For each quantum-vulnerable finding, checks whether a migration to the
recommended NIST PQC standard is:

  VALID              — fully standardized, library support known to exist
  PARTIALLY_SUPPORTED — standard exists but library/runtime support is incomplete
  BLOCKED            — known hard blockers (HSM lock-in, protocol gap, etc.)
  NOT_APPLICABLE     — finding is not quantum-vulnerable (no PQC migration needed)

IMPORTANT: All compatibility assessments are heuristic — derived from
a static knowledge base assembled at build time. The tool does NOT:
  - execute any customer code
  - perform live library version probing
  - guarantee compatibility for a specific deployment environment

Every result carries `is_heuristic=True` and a `library_support` note
that explicitly states the source of any compatibility claim.

Knowledge base last reviewed against:
  - Python cryptography >= 42.0 (liboqs bindings available separately)
  - Java 21+ (Bouncy Castle 1.78+ for ML-KEM preview)
  - Go 1.22+
  - OpenSSL 3.3+ (ML-KEM and SLH-DSA experimental)
  - NIST FIPS 203/204/205 (finalized August 2024)
"""
from __future__ import annotations

from app.models.schemas import (
    Category,
    Finding,
    PQCStatus,
    PQCValidationResult,
    Severity,
)

# ---------------------------------------------------------------------------
# Static PQC compatibility knowledge base
# ---------------------------------------------------------------------------

# Rule ID → (purpose, recommended_pqc, status, reasons, library_support, blockers)
_RULE_PQC_MAP: dict[str, dict] = {
    "QC-RSA-001": {
        "purpose": "key-exchange / signature",
        "recommended_pqc": "ML-KEM (FIPS 203) for key exchange; ML-DSA (FIPS 204) for signatures",
        "status": PQCStatus.PARTIALLY_SUPPORTED,
        "reasons": [
            "ML-KEM (FIPS 203) and ML-DSA (FIPS 204) are NIST-finalized standards (Aug 2024).",
            "Python: oqs-python (liboqs wrapper) provides ML-KEM; standard library support pending.",
            "Java: Bouncy Castle 1.78+ adds ML-KEM/ML-DSA in preview mode.",
            "TLS 1.3 post-quantum hybrid ciphersuites are in IETF draft — not yet RFC.",
            "JWT alg= values for ML-DSA are in IETF draft, not yet assigned.",
        ],
        "library_support": (
            "Python cryptography library (>=42) does not yet include ML-KEM natively. "
            "Use liboqs / oqs-python as interim. Java Bouncy Castle 1.78+ supports ML-KEM in preview."
        ),
        "blockers": [
            "TLS post-quantum hybrid ciphersuites are not yet an RFC — use with caution in production.",
            "JWT PQC signature algorithms are IETF draft, not finalized.",
        ],
    },
    "QC-ECC-001": {
        "purpose": "key-exchange / signature",
        "recommended_pqc": "ML-KEM (FIPS 203) for exchange; ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures",
        "status": PQCStatus.PARTIALLY_SUPPORTED,
        "reasons": [
            "ECC is broken by Shor's algorithm — NIST replacement is ML-KEM for KEM and ML-DSA for signatures.",
            "Hybrid X25519+ML-KEM768 is the recommended transition approach for TLS.",
            "Python oqs-python, Java Bouncy Castle 1.78+, and Go x/crypto/mlkem (experimental) are available.",
            "SLH-DSA (FIPS 205) is hash-based and well-supported but produces larger signatures.",
        ],
        "library_support": (
            "oqs-python (liboqs wrapper) for Python; Bouncy Castle 1.78+ for Java; "
            "golang.org/x/crypto for Go (experimental ML-KEM). "
            "Native integration into standard TLS stacks is still ongoing."
        ),
        "blockers": [
            "ES256/ES384/ES512 JWT algorithms have no standardized PQC replacement in current RFCs.",
            "Client-side ecosystem (browsers, mobile SDKs) support for PQC is still maturing.",
        ],
    },
    "QC-DH-001": {
        "purpose": "key-exchange",
        "recommended_pqc": "ML-KEM (FIPS 203) hybrid with X25519",
        "status": PQCStatus.PARTIALLY_SUPPORTED,
        "reasons": [
            "Classic finite-field DH is vulnerable to quantum Shor's algorithm for discrete log.",
            "Hybrid X25519+ML-KEM768 provides defense-in-depth during the transition period.",
            "IETF RFC 9180 (HPKE) and draft-ietf-tls-hybrid-design discuss the transition path.",
        ],
        "library_support": (
            "oqs-python and Bouncy Castle support ML-KEM but integration into protocol libraries "
            "(e.g., Java JSSE, Python ssl module) requires additional adapter work."
        ),
        "blockers": [
            "Legacy DHE_RSA cipher suites in TLS 1.2 have no direct PQC replacement in that protocol version — upgrade to TLS 1.3 is a prerequisite.",
        ],
    },
}

# Category-level fallbacks for findings not matched by rule ID
_CATEGORY_STATUS_MAP: dict[Category, PQCStatus] = {
    Category.QUANTUM_VULNERABLE_CRYPTO: PQCStatus.PARTIALLY_SUPPORTED,
    Category.CERTIFICATE_ISSUE: PQCStatus.PARTIALLY_SUPPORTED,
    Category.HSM_CLOUD_KMS: PQCStatus.BLOCKED,
    Category.CLASSICAL_CRYPTO_WEAKNESS: PQCStatus.NOT_APPLICABLE,
    Category.SECRET: PQCStatus.NOT_APPLICABLE,
    Category.AUTH_WEAKNESS: PQCStatus.NOT_APPLICABLE,
    Category.DEPENDENCY_CVE: PQCStatus.NOT_APPLICABLE,
    Category.INSECURE_CONFIG: PQCStatus.NOT_APPLICABLE,
    Category.CRYPTO_LIBRARY: PQCStatus.PARTIALLY_SUPPORTED,
    Category.BINARY_ARTIFACT: PQCStatus.BLOCKED,
}

_HSM_REASONS = [
    "HSM/cloud KMS assets are hardware- or vendor-bound.",
    "PQC support depends on HSM firmware/vendor roadmap — cannot be assessed statically.",
    "AWS KMS, Azure Key Vault, and Google Cloud KMS have announced PQC roadmaps but availability varies.",
]
_HSM_BLOCKERS = [
    "Requires vendor HSM firmware update or migration to a PQC-capable HSM.",
    "Cannot be migrated without vendor coordination.",
]

_BINARY_REASONS = [
    "Crypto use found in a compiled binary — source is not visible for static analysis.",
    "Migration feasibility cannot be determined without access to the source code.",
]


def _purpose_from_category(category: Category, rule_id: str | None) -> str:
    if rule_id and rule_id in _RULE_PQC_MAP:
        return _RULE_PQC_MAP[rule_id]["purpose"]
    return {
        Category.QUANTUM_VULNERABLE_CRYPTO: "key-exchange or signature (inferred)",
        Category.CERTIFICATE_ISSUE: "certificate signing / TLS",
        Category.HSM_CLOUD_KMS: "key management",
        Category.CRYPTO_LIBRARY: "cryptographic library usage",
        Category.BINARY_ARTIFACT: "unknown (binary)",
    }.get(category, "unknown")


def validate_pqc_migrations(findings: list[Finding]) -> list[PQCValidationResult]:
    """Validate each finding's PQC migration feasibility and return results."""
    results: list[PQCValidationResult] = []

    for f in findings:
        rule_kb = _RULE_PQC_MAP.get(f.matched_pattern or "")

        if f.category == Category.HSM_CLOUD_KMS:
            results.append(PQCValidationResult(
                finding_id=f.id,
                finding_title=f.title,
                current_algorithm=f.title,
                purpose="key management",
                recommended_pqc="Vendor-specific PQC HSM or cloud KMS PQC key type",
                status=PQCStatus.BLOCKED,
                reasons=_HSM_REASONS,
                library_support="Vendor HSM firmware / Cloud provider roadmap required.",
                known_blockers=_HSM_BLOCKERS,
            ))
            continue

        if f.category == Category.BINARY_ARTIFACT:
            results.append(PQCValidationResult(
                finding_id=f.id,
                finding_title=f.title,
                current_algorithm=f.title,
                purpose="unknown (binary artifact)",
                status=PQCStatus.BLOCKED,
                reasons=_BINARY_REASONS,
                known_blockers=["Source code required for migration assessment."],
            ))
            continue

        if f.category not in (Category.QUANTUM_VULNERABLE_CRYPTO, Category.CERTIFICATE_ISSUE, Category.CRYPTO_LIBRARY):
            results.append(PQCValidationResult(
                finding_id=f.id,
                finding_title=f.title,
                current_algorithm=f.title,
                purpose=_purpose_from_category(f.category, f.matched_pattern),
                status=PQCStatus.NOT_APPLICABLE,
                reasons=[
                    "This finding relates to a classical weakness or secret — PQC migration is not required.",
                    "Fix using classical best practices (SHA-256, AES-256-GCM, etc.).",
                ],
            ))
            continue

        if rule_kb:
            results.append(PQCValidationResult(
                finding_id=f.id,
                finding_title=f.title,
                current_algorithm=f.title,
                purpose=rule_kb["purpose"],
                recommended_pqc=rule_kb["recommended_pqc"],
                status=rule_kb["status"],
                reasons=rule_kb["reasons"],
                library_support=rule_kb["library_support"],
                known_blockers=rule_kb.get("blockers", []),
            ))
        else:
            # Fallback for quantum-vulnerable findings not in the rule map
            status = _CATEGORY_STATUS_MAP.get(f.category, PQCStatus.PARTIALLY_SUPPORTED)
            results.append(PQCValidationResult(
                finding_id=f.id,
                finding_title=f.title,
                current_algorithm=f.title,
                purpose=_purpose_from_category(f.category, f.matched_pattern),
                recommended_pqc=f.nist_pqc_recommendation or "See NIST PQC standards (FIPS 203/204/205)",
                status=status,
                reasons=[
                    "This finding is quantum-vulnerable per NIST guidance.",
                    f"Recommended migration: {f.nist_pqc_recommendation or 'NIST PQC standards'}.",
                    "Specific library and runtime support has not been validated for this rule — manual verification required.",
                ],
                known_blockers=["No automated compatibility check available for this pattern."],
            ))

    return results
