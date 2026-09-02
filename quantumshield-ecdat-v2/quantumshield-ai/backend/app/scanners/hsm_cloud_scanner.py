"""
Hardware Security Module & Cloud KMS Scanner
===============================================
Detects usage of hardware-backed or cloud-managed key services via SDK/API
reference patterns in source and dependency manifests. This can't inspect
the actual HSM/KMS configuration (that lives outside the codebase, in the
cloud account or physical device) — it flags *that* a system relies on one,
which is itself valuable inventory: these are exactly the assets that need a
vendor conversation about their own PQC roadmap, since the org doesn't
control the cryptographic implementation directly.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from pathlib import Path

from app.models.schemas import ArtifactType, Category, Finding, Severity


@dataclass
class HsmRule:
    id: str
    pattern: re.Pattern
    title: str
    vendor: str
    description: str


RULES: list[HsmRule] = [
    HsmRule(
        id="HSM-AWSKMS-001",
        pattern=re.compile(r"boto3\.client\(['\"]kms['\"]\)|\bAWSKMS\b|\baws_kms\b|\bkms:Encrypt\b|\bkms:Decrypt\b"),
        title="AWS KMS usage detected",
        vendor="AWS Key Management Service",
        description="Application delegates key management to AWS KMS. The org doesn't control KMS's internal cryptographic implementation directly — its PQC readiness depends on AWS's own migration timeline.",
    ),
    HsmRule(
        id="HSM-AZUREKV-001",
        pattern=re.compile(r"\b(azure\.keyvault|KeyVaultClient|AZURE_KEY_VAULT)\b"),
        title="Azure Key Vault usage detected",
        vendor="Azure Key Vault",
        description="Application delegates key management to Azure Key Vault. PQC readiness depends on Microsoft's migration timeline for the underlying HSMs.",
    ),
    HsmRule(
        id="HSM-GCPKMS-001",
        pattern=re.compile(r"\b(google\.cloud\.kms|GCP_KMS|CloudKMS)\b"),
        title="Google Cloud KMS usage detected",
        vendor="Google Cloud KMS",
        description="Application delegates key management to Google Cloud KMS. PQC readiness depends on Google's migration timeline for the underlying HSMs.",
    ),
    HsmRule(
        id="HSM-PKCS11-001",
        pattern=re.compile(r"\b(pkcs11|PKCS#11|PKCS11Session)\b", re.IGNORECASE),
        title="PKCS#11 hardware token/HSM interface detected",
        vendor="Generic HSM (PKCS#11)",
        description="Application interfaces with a hardware security module via the PKCS#11 standard. Firmware/vendor PQC support should be confirmed directly with the HSM manufacturer.",
    ),
    HsmRule(
        id="HSM-CLOUDHSM-001",
        pattern=re.compile(r"\b(CloudHSM|cloudhsm)\b"),
        title="AWS CloudHSM usage detected",
        vendor="AWS CloudHSM",
        description="Application uses a dedicated single-tenant HSM instance (CloudHSM). Confirm PQC algorithm support directly with AWS's CloudHSM roadmap.",
    ),
    HsmRule(
        id="HSM-VENDOR-001",
        pattern=re.compile(r"\b(Thales|SafeNet|nCipher|Luna\s?HSM|Utimaco)\b"),
        title="Named HSM vendor product referenced",
        vendor="Third-party HSM",
        description="Application references a specific hardware vendor's HSM product. Vendor-specific firmware update or replacement may be required for PQC support.",
    ),
]

SCANNABLE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".yml", ".yaml", ".json", ".conf", ".cfg", ".toml", "pom.xml"}
IGNORE_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}


def scan_hsm_cloud_kms(root_path: str) -> list[Finding]:
    root = Path(root_path)
    findings: list[Finding] = []

    for file_path in root.rglob("*"):
        if not file_path.is_file() or any(part in IGNORE_DIRS for part in file_path.parts):
            continue
        if file_path.suffix.lower() not in SCANNABLE_EXTENSIONS and file_path.name not in ("pom.xml",):
            continue
        try:
            text = file_path.read_text(errors="ignore")
        except OSError:
            continue

        rel = str(file_path.relative_to(root))
        seen_rules_in_file = set()
        for rule in RULES:
            if rule.id in seen_rules_in_file:
                continue
            match = rule.pattern.search(text)
            if match:
                seen_rules_in_file.add(rule.id)
                line_no = text.count("\n", 0, match.start()) + 1
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        category=Category.HSM_CLOUD_KMS,
                        severity=Severity.INFO,
                        title=rule.title,
                        description=rule.description,
                        file_path=rel,
                        line_number=line_no,
                        matched_pattern=rule.id,
                        artifact_type=ArtifactType.RELATED_MATERIAL,
                        remediation=f"Confirm {rule.vendor}'s published post-quantum cryptography roadmap and supported algorithm list.",
                        extra={"vendor": rule.vendor},
                    )
                )

    return findings
