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


if __name__ == "__main__":
    import argparse
    import sys
    from app.scoring.engine import compute_scores

    parser = argparse.ArgumentParser(
        prog="quantumshield-scan",
        description="QuantumShield AI — Cryptographic & Quantum-Readiness Scanner CLI",
    )
    parser.add_argument("target", help="Directory path to scan")
    parser.add_argument("--horizon", type=float, default=10.0, help="Quantum threat horizon in years (default: 10)")
    parser.add_argument("--offline", action="store_true", help="Skip online CVE/OSV lookups")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    if not target_dir.exists():
        print(f"Error: Target directory '{target_dir}' does not exist.", file=sys.stderr)
        sys.exit(1)

    print(f"\n========================================================")
    print(f"[+] QuantumShield AI -- Security & CBOM Scanner")
    print(f"========================================================")
    print(f"Target: {target_dir}")
    print(f"Threat Horizon (Z): {args.horizon} years\n")

    mosca_cfg = MoscaConfig(quantum_threat_horizon_years=args.horizon)
    findings, files_count = run_full_scan(str(target_dir), mosca_config=mosca_cfg, skip_osv_lookup=args.offline)
    scores = compute_scores(findings)

    print(f"Scanned {files_count} files. Identified {len(findings)} findings.\n")
    print(f"--- SCORE SUMMARY ---")
    print(f"Overall Health:       {scores.overall_health}/100 (Grade: {scores.grade})")
    print(f"Security Score:       {scores.security_score}/100")
    print(f"Quantum Readiness:    {scores.quantum_readiness_score}/100")
    print(f"Compliance Score:     {scores.compliance_score}/100")
    print(f"Criticality Score:    {scores.criticality_score}/100\n")

    print(f"--- DETECTED FINDINGS ({len(findings)}) ---")
    for f in findings:
        harvest_tag = " [HARVEST-NOW RISK]" if f.quantum_harvest_now_risk else ""
        print(f"[{f.severity.value.upper():<8}] {f.title}{harvest_tag}")
        print(f"           File: {f.file_path}" + (f":{f.line_number}" if f.line_number else ""))
        if f.nist_pqc_recommendation:
            print(f"           NIST PQC: {f.nist_pqc_recommendation}")
        if f.mosca and f.mosca.risk_level.value == "at_risk":
            print(f"           Mosca: AT RISK (X+Y={f.mosca.x_plus_y} > Z={f.mosca.quantum_threat_horizon_years})")
        print()

    print(f"========================================================")
    print(f"Scan complete. Open frontend dashboard for full CBOM & interactive simulation.")
    print(f"========================================================\n")

