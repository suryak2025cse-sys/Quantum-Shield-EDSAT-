"""
CycloneDX 1.6 CBOM Export
============================
Maps scan findings to CycloneDX 1.6's native "cryptographic-asset" component
type (introduced in the 1.6 spec, upstreamed from IBM's CBOM research) so
the output is a real, standardized, machine-readable Cryptographic Bill of
Materials — not a bespoke JSON shape. Schema reference: CycloneDX 1.6
cryptoProperties (assetType: algorithm | certificate | protocol |
related-material; algorithmProperties; certificateProperties).

This targets the documented structure of the spec. It has not been run
through the official CycloneDX JSON schema validator, so treat it as a
faithful implementation rather than a certified-conformant one until that
validation step is added.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.models.schemas import ArtifactType, Category, Finding, ScanSummary

CYCLONEDX_SPEC_VERSION = "1.6"

# Map our Category to CycloneDX's classicalSecurityLevel / nistQuantumSecurityLevel
# conventions where meaningful. nistQuantumSecurityLevel of 0 signals "broken by
# a sufficiently large quantum computer" per the spec's intent for legacy algorithms.
QUANTUM_SECURITY_LEVEL_BY_CATEGORY = {
    Category.QUANTUM_VULNERABLE_CRYPTO: 0,
    Category.CERTIFICATE_ISSUE: 0,
}


def _algorithm_properties(finding: Finding) -> dict:
    props = {}
    if finding.category in QUANTUM_SECURITY_LEVEL_BY_CATEGORY:
        props["nistQuantumSecurityLevel"] = QUANTUM_SECURITY_LEVEL_BY_CATEGORY[finding.category]
    if finding.matched_pattern:
        props["parameterSetIdentifier"] = finding.matched_pattern
    return props


def _certificate_properties(finding: Finding) -> dict:
    extra = finding.extra or {}
    return {
        "subjectName": extra.get("subject"),
        "issuerName": extra.get("issuer"),
        "notAfter": extra.get("not_valid_after"),
        "signatureAlgorithmRef": extra.get("signature_algorithm"),
        "certificateFormat": "X.509",
    }


def _finding_to_component(finding: Finding) -> dict:
    crypto_properties: dict = {"assetType": finding.artifact_type.value}

    if finding.artifact_type == ArtifactType.ALGORITHM:
        crypto_properties["algorithmProperties"] = _algorithm_properties(finding)
    elif finding.artifact_type == ArtifactType.CERTIFICATE:
        crypto_properties["certificateProperties"] = {k: v for k, v in _certificate_properties(finding).items() if v is not None}
    elif finding.artifact_type == ArtifactType.RELATED_MATERIAL:
        crypto_properties["relatedCryptoMaterialProperties"] = {"type": "key", "state": "active"}

    component = {
        "type": "cryptographic-asset",
        "bom-ref": finding.id,
        "name": finding.title,
        "description": finding.description,
        "cryptoProperties": crypto_properties,
        "properties": [
            {"name": "quantumshield:file_path", "value": f"{finding.file_path}" + (f":{finding.line_number}" if finding.line_number else "")},
            {"name": "quantumshield:severity", "value": finding.severity.value},
            {"name": "quantumshield:criticality", "value": finding.criticality.value if finding.criticality else "unclassified"},
            {"name": "quantumshield:exposure", "value": finding.exposure.value},
        ],
    }

    if finding.mosca:
        component["properties"].append({"name": "quantumshield:mosca_risk", "value": finding.mosca.risk_level.value})
        component["properties"].append({"name": "quantumshield:mosca_x_plus_y_years", "value": str(finding.mosca.x_plus_y)})
        component["properties"].append({"name": "quantumshield:mosca_threat_horizon_years", "value": str(finding.mosca.quantum_threat_horizon_years)})

    if finding.nist_pqc_recommendation:
        component["properties"].append({"name": "quantumshield:pqc_recommendation", "value": finding.nist_pqc_recommendation})

    return component


def generate_cbom(scan: ScanSummary) -> dict:
    """Produces a CycloneDX 1.6-shaped CBOM document for a completed scan."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {"type": "application", "name": "QuantumShield AI", "version": "0.1.0"}
                ]
            },
            "component": {
                "type": "application",
                "name": scan.target_name,
                "bom-ref": scan.scan_id,
            },
        },
        "components": [_finding_to_component(f) for f in scan.findings],
    }
