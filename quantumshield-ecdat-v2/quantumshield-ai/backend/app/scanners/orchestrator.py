"""
Scan Orchestrator
===================
Single entry point that runs every scanner (crypto/secrets, certificates,
dependencies, HSM/cloud KMS, binaries) against a directory, then annotates
every resulting Finding with:
  - business criticality (classification.py)
  - exposure (internal/external/unknown) (exposure.py)
  - Mosca's algorithm risk assessment, for quantum-vulnerable artifacts (mosca.py)

This is the one function both the plain-directory upload path and the
container-image path call, so both get identical analytical depth.
"""
from __future__ import annotations

from pathlib import Path

from app.analysis import mosca
from app.analysis.classification import ClassificationConfig, classify
from app.analysis.exposure import scan_exposure_signals
from app.analysis.mosca import QUANTUM_VULNERABLE_CATEGORIES, MoscaConfig
from app.models.schemas import Finding
from app.scanners.binary_scanner import scan_binaries
from app.scanners.certificate_scanner import scan_certificates
from app.scanners.crypto_scanner import scan_directory as scan_crypto_and_secrets
from app.scanners.dependency_scanner import scan_dependencies
from app.scanners.hsm_cloud_scanner import scan_hsm_cloud_kms


def run_full_scan(
    root_path: str,
    classification_config: ClassificationConfig | None = None,
    mosca_config: MoscaConfig | None = None,
    skip_osv_lookup: bool = False,
) -> tuple[list[Finding], int]:
    """Runs the complete scanner suite against a directory and returns
    (annotated findings, files_scanned)."""

    crypto_secret_findings, files_scanned = scan_crypto_and_secrets(root_path)
    cert_findings = scan_certificates(root_path)
    dep_findings = scan_dependencies(root_path, skip_network=skip_osv_lookup)
    hsm_findings = scan_hsm_cloud_kms(root_path)
    binary_findings = scan_binaries(root_path)

    all_findings = crypto_secret_findings + cert_findings + dep_findings + hsm_findings + binary_findings

    # Exposure is assessed once for the whole project (a deployable unit
    # typically shares one exposure profile) and applied to every finding.
    exposure = scan_exposure_signals(root_path)

    for finding in all_findings:
        criticality, _reason = classify(finding.file_path, classification_config)
        finding.criticality = criticality
        finding.exposure = exposure

        is_quantum_vulnerable = finding.category in QUANTUM_VULNERABLE_CATEGORIES or finding.quantum_harvest_now_risk
        finding.mosca = mosca.assess(finding.category, finding.file_path, is_quantum_vulnerable, mosca_config)

    return all_findings, files_scanned
