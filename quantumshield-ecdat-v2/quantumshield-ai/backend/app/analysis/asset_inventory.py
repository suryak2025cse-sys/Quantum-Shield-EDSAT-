"""
Cryptographic Asset Normalization & Inventory
==============================================
Deduplicates and groups raw scan findings into canonical, normalized
CryptographicAsset inventory items with stable fingerprints, aggregated
locations, risk profiles, and linked findings.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Sequence

from app.models.schemas import (
    ArtifactType,
    Category,
    Criticality,
    Exposure,
    Finding,
    NormalizedAsset,
    Severity,
)

_SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def _extract_primitive_name(finding: Finding) -> tuple[str, str | None]:
    """Extract (canonical_primitive_name, version_or_key_size) from finding."""
    extra = finding.extra or {}
    pattern = finding.matched_pattern or ""

    if extra.get("library"):
        return extra["library"], extra.get("version")

    if extra.get("algorithm"):
        return extra["algorithm"], None

    if finding.artifact_type == ArtifactType.CERTIFICATE:
        key_algo = extra.get("public_key_algorithm", "X.509 Certificate")
        key_size = extra.get("key_size_bits")
        return key_algo, f"{key_size} bits" if key_size else None

    # Derive from title / pattern
    if "RSA" in pattern or "RSA" in finding.title:
        return "RSA", None
    if "ECC" in pattern or "ECDSA" in pattern or "Elliptic" in finding.title:
        return "ECDSA / ECC", None
    if "DH" in pattern or "Diffie" in finding.title:
        return "Diffie-Hellman", None
    if "MD5" in pattern or "MD5" in finding.title:
        return "MD5", None
    if "SHA1" in pattern or "SHA-1" in finding.title:
        return "SHA-1", None
    if "DES" in pattern or "DES" in finding.title:
        return "DES / 3DES", None
    if "ECB" in pattern or "ECB" in finding.title:
        return "AES-ECB", None
    if "TLS" in pattern or "TLS" in finding.title:
        return "Legacy TLS", None
    if "JWT" in pattern or "JWT" in finding.title:
        return "JWT (alg: none)", None

    return finding.title, None


def _generate_fingerprint(finding: Finding, primitive_name: str, version: str | None) -> str:
    """Generate deterministic, stable asset fingerprint."""
    extra = finding.extra or {}
    asset_type = finding.artifact_type.value

    if finding.artifact_type == ArtifactType.CERTIFICATE and extra.get("subject"):
        raw = f"CERT:{extra['subject']}:{extra.get('issuer', '')}"
    elif finding.artifact_type == ArtifactType.LIBRARY and extra.get("library"):
        raw = f"LIB:{extra['library']}:{extra.get('version', 'any')}:{extra.get('ecosystem', '')}"
    else:
        raw = f"{asset_type}:{primitive_name}:{version or ''}"

    digest = hashlib.sha256(raw.encode()).hexdigest()[:12]
    return f"ASSET-{asset_type[:4].upper()}-{digest}"


def build_normalized_inventory(findings: Sequence[Finding]) -> list[NormalizedAsset]:
    """
    Groups raw findings into deduplicated NormalizedAsset inventory items.
    """
    groups: dict[str, list[Finding]] = defaultdict(list)
    primitive_map: dict[str, tuple[str, str | None]] = {}

    for f in findings:
        prim, ver = _extract_primitive_name(f)
        fp = _generate_fingerprint(f, prim, ver)
        groups[fp].append(f)
        primitive_map[fp] = (prim, ver)

    inventory: list[NormalizedAsset] = []

    for fp, grouped_findings in groups.items():
        first = grouped_findings[0]
        prim, ver = primitive_map[fp]

        # Highest severity in group
        highest_severity = max(
            (f.severity for f in grouped_findings),
            key=lambda s: _SEVERITY_ORDER.get(s, 0),
        )

        # Unique locations (file:line)
        locations = []
        for f in grouped_findings:
            loc = f.file_path + (f":{f.line_number}" if f.line_number else "")
            if loc not in locations:
                locations.append(loc)

        # Confidence: User Configured > Detected Evidence > Inferred Heuristic
        confidence = "Detected Evidence"
        if any(f.extra.get("detection_method") == "strings-based binary scan" for f in grouped_findings):
            confidence = "Inferred Heuristic"

        # Mosca assessment & PQC rec
        mosca_risk = None
        data_lifetime = None
        migration_time = None
        for f in grouped_findings:
            if f.mosca:
                mosca_risk = f.mosca.risk_level.value
                data_lifetime = f.mosca.data_lifetime_years
                migration_time = f.mosca.migration_time_years
                break

        pqc_rec = next((f.nist_pqc_recommendation for f in grouped_findings if f.nist_pqc_recommendation), None)
        criticality = next((f.criticality for f in grouped_findings if f.criticality), None)
        exposure = next((f.exposure for f in grouped_findings if f.exposure != Exposure.UNKNOWN), Exposure.UNKNOWN)

        name = prim
        if first.artifact_type == ArtifactType.CERTIFICATE and first.extra.get("subject"):
            name = f"Cert: {first.extra['subject']}"
        elif first.artifact_type == ArtifactType.LIBRARY and first.extra.get("library"):
            name = f"Lib: {first.extra['library']}"

        inventory.append(
            NormalizedAsset(
                asset_id=fp,
                asset_type=first.artifact_type,
                name=name,
                algorithm_or_primitive=prim,
                version_or_key_size=ver,
                locations=locations,
                occurrences_count=len(grouped_findings),
                severity=highest_severity,
                criticality=criticality,
                exposure=exposure,
                data_lifetime_years=data_lifetime,
                migration_time_years=migration_time,
                mosca_risk=mosca_risk,
                pqc_recommendation=pqc_rec,
                confidence=confidence,
                linked_finding_ids=[f.id for f in grouped_findings],
                metadata={
                    "category": first.category.value,
                    "cwe_id": first.cwe_id,
                    "harvest_now_risk": any(f.quantum_harvest_now_risk for f in grouped_findings),
                },
            )
        )

    # Sort by severity descending
    inventory.sort(key=lambda a: _SEVERITY_ORDER.get(a.severity, 0), reverse=True)
    return inventory
