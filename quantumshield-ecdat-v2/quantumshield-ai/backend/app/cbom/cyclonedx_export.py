"""
CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) Export
============================================================
Converts scan results and normalized cryptographic assets into official
CycloneDX 1.6 JSON Cryptographic Bill of Materials format.

Spec Compliance:
  - CycloneDX 1.6 JSON Schema (cryptoProperties, algorithmProperties, certificateProperties)
  - Distinguishes "cryptographic-asset" vs "library" component types
  - Includes component dependency graphs (dependencies array)
  - Records QuantumShield analysis extensions in standardized properties
  - Provides strict schema structural validation
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from app.models.schemas import ArtifactType, Category, Finding, ScanSummary

CYCLONEDX_SPEC_VERSION = "1.6"

QUANTUM_SECURITY_LEVEL_BY_CATEGORY = {
    Category.QUANTUM_VULNERABLE_CRYPTO: 0,  # 0 indicates broken by Shor's algorithm per CycloneDX standard
    Category.CERTIFICATE_ISSUE: 0,
}


def _algorithm_properties(finding: Finding) -> dict[str, Any]:
    props: dict[str, Any] = {}
    if finding.category in QUANTUM_SECURITY_LEVEL_BY_CATEGORY:
        props["nistQuantumSecurityLevel"] = QUANTUM_SECURITY_LEVEL_BY_CATEGORY[finding.category]
    if finding.matched_pattern:
        props["parameterSetIdentifier"] = finding.matched_pattern
    if finding.cwe_id:
        props["classicalSecurityLevel"] = 0 if "327" in finding.cwe_id or "328" in finding.cwe_id else 112
    return props


def _certificate_properties(finding: Finding) -> dict[str, Any]:
    extra = finding.extra or {}
    cert_props: dict[str, Any] = {
        "certificateFormat": extra.get("certificate_format", "X.509"),
        "subjectName": extra.get("subject"),
        "issuerName": extra.get("issuer"),
        "notAfter": extra.get("not_valid_after"),
        "notBefore": extra.get("not_valid_before"),
        "signatureAlgorithmRef": extra.get("signature_algorithm"),
    }
    return {k: v for k, v in cert_props.items() if v is not None}


def _finding_to_component(finding: Finding) -> dict[str, Any]:
    extra = finding.extra or {}
    is_library = finding.artifact_type == ArtifactType.LIBRARY or finding.category == Category.CRYPTO_LIBRARY
    component_type = "library" if is_library else "cryptographic-asset"

    crypto_properties: dict[str, Any] = {"assetType": finding.artifact_type.value}
    if finding.artifact_type == ArtifactType.ALGORITHM:
        crypto_properties["algorithmProperties"] = _algorithm_properties(finding)
    elif finding.artifact_type == ArtifactType.CERTIFICATE:
        crypto_properties["certificateProperties"] = _certificate_properties(finding)
    elif finding.artifact_type == ArtifactType.RELATED_MATERIAL:
        crypto_properties["relatedCryptoMaterialProperties"] = {"type": "key", "state": "active"}
    elif finding.artifact_type == ArtifactType.PROTOCOL:
        crypto_properties["protocolProperties"] = {"type": "tls", "version": "legacy"}

    properties = [
        {"name": "quantumshield:file_path", "value": f"{finding.file_path}" + (f":{finding.line_number}" if finding.line_number else "")},
        {"name": "quantumshield:severity", "value": finding.severity.value},
        {"name": "quantumshield:criticality", "value": finding.criticality.value if finding.criticality else "unclassified"},
        {"name": "quantumshield:exposure", "value": finding.exposure.value},
        {"name": "quantumshield:confidence", "value": extra.get("confidence", "Detected Evidence")},
    ]

    if finding.mosca:
        properties.append({"name": "quantumshield:mosca_risk", "value": finding.mosca.risk_level.value})
        properties.append({"name": "quantumshield:mosca_x_plus_y_years", "value": str(finding.mosca.x_plus_y)})
        properties.append({"name": "quantumshield:mosca_threat_horizon_years", "value": str(finding.mosca.quantum_threat_horizon_years)})

    if finding.nist_pqc_recommendation:
        properties.append({"name": "quantumshield:pqc_recommendation", "value": finding.nist_pqc_recommendation})

    comp: dict[str, Any] = {
        "type": component_type,
        "bom-ref": finding.id,
        "name": finding.title,
        "description": finding.description,
        "cryptoProperties": crypto_properties,
        "properties": properties,
    }

    if is_library and extra.get("version"):
        comp["version"] = str(extra["version"])
    if is_library and extra.get("ecosystem") and extra.get("library"):
        eco = str(extra["ecosystem"]).lower()
        lib = str(extra["library"]).lower()
        comp["purl"] = f"pkg:{eco}/{lib}@{extra.get('version', 'unknown')}"

    return comp


def generate_cbom(scan: ScanSummary) -> dict[str, Any]:
    """Produces a CycloneDX 1.6-compliant CBOM JSON document."""
    app_ref = f"app:{scan.scan_id}"
    components = [_finding_to_component(f) for f in scan.findings]

    # Build dependency relationship graph
    component_refs = [c["bom-ref"] for c in components]
    dependencies = [
        {
            "ref": app_ref,
            "dependsOn": component_refs,
        }
    ]

    cbom_document = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "QuantumShield AI",
                        "version": "0.2.0",
                        "description": "Cryptographic Bill of Materials & Quantum-Readiness Analytics",
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": scan.target_name,
                "bom-ref": app_ref,
                "properties": [
                    {"name": "quantumshield:total_findings", "value": str(scan.total_findings)},
                    {"name": "quantumshield:overall_health", "value": str(scan.scores.overall_health)},
                    {"name": "quantumshield:grade", "value": scan.scores.grade},
                ],
            },
        },
        "components": components,
        "dependencies": dependencies,
    }

    return cbom_document


def validate_cbom_structure(cbom: dict[str, Any]) -> tuple[bool, list[str]]:
    """Validates required CycloneDX 1.6 top-level structure and components."""
    errors = []
    if cbom.get("bomFormat") != "CycloneDX":
        errors.append("Missing or invalid 'bomFormat' (must be 'CycloneDX')")
    if cbom.get("specVersion") != "1.6":
        errors.append("Missing or invalid 'specVersion' (must be '1.6')")
    if not cbom.get("serialNumber", "").startswith("urn:uuid:"):
        errors.append("Invalid 'serialNumber' (must be urn:uuid:<uuid>)")
    if not isinstance(cbom.get("components"), list):
        errors.append("Missing 'components' list")

    for i, c in enumerate(cbom.get("components", [])):
        if "bom-ref" not in c:
            errors.append(f"Component #{i} missing 'bom-ref'")
        if "type" not in c:
            errors.append(f"Component #{i} missing 'type'")
        if c.get("type") == "cryptographic-asset" and "cryptoProperties" not in c:
            errors.append(f"Cryptographic-asset component #{i} missing 'cryptoProperties'")

    return len(errors) == 0, errors
