"""
Cryptography & Quantum-Readiness Scanner
==========================================
Static analysis over source files and configuration manifests to build a lightweight
Cryptographic Bill of Materials (CBOM).
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from pathlib import Path

from app.models.schemas import ArtifactType, Category, Finding, Severity


@dataclass
class CryptoRule:
    id: str
    pattern: re.Pattern
    title: str
    category: Category
    severity: Severity
    description: str
    cwe_id: str | None
    nist_pqc_recommendation: str | None
    quantum_harvest_now_risk: bool
    remediation: str
    artifact_type: ArtifactType = ArtifactType.ALGORITHM


RULES: list[CryptoRule] = [
    CryptoRule(
        id="QC-RSA-001",
        pattern=re.compile(r"\b(RSA\.generate|rsa\.generate_private_key|RSA_generate_key|new\s+RSACryptoServiceProvider|RSAKeyGenParameterSpec|Crypto\.PublicKey\.RSA|RS256|RS384|RS512)\b"),
        title="RSA key generation / RSA-based signing detected",
        category=Category.QUANTUM_VULNERABLE_CRYPTO,
        severity=Severity.HIGH,
        description="RSA relies on integer factorization hardness, broken in polynomial time by Shor's algorithm on a CRQC.",
        cwe_id="CWE-327",
        nist_pqc_recommendation="ML-KEM (FIPS 203) for key exchange, ML-DSA (FIPS 204) for signatures",
        quantum_harvest_now_risk=True,
        remediation="Plan migration to hybrid classical+PQC scheme (X25519+ML-KEM-768) and ML-DSA / SLH-DSA for signatures.",
        artifact_type=ArtifactType.ALGORITHM,
    ),
    CryptoRule(
        id="QC-ECC-001",
        pattern=re.compile(r"\b(ec\.generate_private_key|ECDSA|ECDH|SECP256R1|SECP384R1|SECP521R1|prime256v1|secp256k1|ES256|ES384|ES512|EllipticCurve)\b"),
        title="Elliptic-curve cryptography (ECC/ECDSA/ECDH) detected",
        category=Category.QUANTUM_VULNERABLE_CRYPTO,
        severity=Severity.HIGH,
        description="ECC relies on elliptic-curve discrete logs, broken by Shor's algorithm with fewer qubits than RSA.",
        cwe_id="CWE-327",
        nist_pqc_recommendation="ML-KEM (FIPS 203) for exchange, ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures",
        quantum_harvest_now_risk=True,
        remediation="Use hybrid key encapsulation (X25519+ML-KEM) and transition to ML-DSA signatures.",
        artifact_type=ArtifactType.ALGORITHM,
    ),
    CryptoRule(
        id="QC-DH-001",
        pattern=re.compile(r"\b(Diffie[-_]?Hellman|DHParameterSpec|dhparam|DHE_RSA|DH_anon)\b"),
        title="Classic Diffie-Hellman key exchange detected",
        category=Category.QUANTUM_VULNERABLE_CRYPTO,
        severity=Severity.HIGH,
        description="Finite-field Diffie-Hellman is vulnerable to Shor's algorithm, threatening session forward secrecy.",
        cwe_id="CWE-327",
        nist_pqc_recommendation="ML-KEM (FIPS 203) hybrid key exchange",
        quantum_harvest_now_risk=True,
        remediation="Replace with hybrid ML-KEM key encapsulation.",
        artifact_type=ArtifactType.ALGORITHM,
    ),
    CryptoRule(
        id="CS-SHA1-001",
        pattern=re.compile(r"\b(SHA1|SHA-1|sha1\(|hashlib\.sha1|MessageDigest\.getInstance\([\"']SHA-1[\"']\))\b"),
        title="SHA-1 hash function in use",
        category=Category.CLASSICAL_CRYPTO_WEAKNESS,
        severity=Severity.MEDIUM,
        description="SHA-1 has practical collision attacks and is deprecated by NIST for digital signatures.",
        cwe_id="CWE-328",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Upgrade to SHA-256 or SHA-3.",
        artifact_type=ArtifactType.ALGORITHM,
    ),
    CryptoRule(
        id="CS-MD5-001",
        pattern=re.compile(r"\b(MD5|md5\(|hashlib\.md5|MessageDigest\.getInstance\([\"']MD5[\"']\))\b"),
        title="MD5 hash function in use",
        category=Category.CLASSICAL_CRYPTO_WEAKNESS,
        severity=Severity.HIGH,
        description="MD5 is cryptographically broken and trivial to collide.",
        cwe_id="CWE-328",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Replace with SHA-256 / SHA-3 for integrity, or Argon2id / bcrypt for passwords.",
        artifact_type=ArtifactType.ALGORITHM,
    ),
    CryptoRule(
        id="CS-DES-001",
        pattern=re.compile(r"\b(DES|3DES|TripleDES|RC4|ARC4|Blowfish)\b"),
        title="Legacy weak symmetric cipher (DES/3DES/RC4) detected",
        category=Category.CLASSICAL_CRYPTO_WEAKNESS,
        severity=Severity.HIGH,
        description="DES (56-bit) and RC4 are insecure; 3DES is deprecated (Sweet32 attack).",
        cwe_id="CWE-327",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Migrate to AES-256-GCM or ChaCha20-Poly1305.",
        artifact_type=ArtifactType.ALGORITHM,
    ),
    CryptoRule(
        id="CS-ECB-001",
        pattern=re.compile(r"\bAES\.MODE_ECB\b|Cipher\.getInstance\([\"']AES/ECB"),
        title="AES used in insecure ECB mode",
        category=Category.CLASSICAL_CRYPTO_WEAKNESS,
        severity=Severity.HIGH,
        description="ECB mode encrypts identical plaintext blocks to identical ciphertext, leaking pattern structure.",
        cwe_id="CWE-327",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Use authenticated AES-256-GCM mode.",
        artifact_type=ArtifactType.ALGORITHM,
    ),
    CryptoRule(
        id="PROTO-TLS-001",
        pattern=re.compile(r"\b(TLSv1\.0|TLSv1\.1|SSLv2|SSLv3|PROTOCOL_TLSv1\b|PROTOCOL_SSLv3)\b"),
        title="Legacy TLS/SSL protocol version allowed",
        category=Category.CLASSICAL_CRYPTO_WEAKNESS,
        severity=Severity.HIGH,
        description="TLS 1.0/1.1 and SSL versions are deprecated (RFC 8996) due to known protocol flaws (POODLE, BEAST).",
        cwe_id="CWE-326",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Enforce TLS 1.3 minimum (TLS 1.2 floor only where strictly required).",
        artifact_type=ArtifactType.PROTOCOL,
    ),
    CryptoRule(
        id="PROTO-SSH-001",
        pattern=re.compile(r"\b(ssh-rsa|ssh-dss|diffie-hellman-group1-sha1|diffie-hellman-group14-sha1)\b"),
        title="Legacy SSH key/kex algorithm configuration detected",
        category=Category.CLASSICAL_CRYPTO_WEAKNESS,
        severity=Severity.HIGH,
        description="Legacy SSH configuration permits SHA-1 or broken asymmetric keys (ssh-dss/ssh-rsa).",
        cwe_id="CWE-326",
        nist_pqc_recommendation="Transition SSH to sntrup761x25519-sha512@openssh.com (OpenSSH PQC hybrid)",
        quantum_harvest_now_risk=True,
        remediation="Enforce OpenSSH PQC hybrid key exchange (sntrup761x25519 / ML-KEM) and ed25519 hostkeys.",
        artifact_type=ArtifactType.PROTOCOL,
    ),
    CryptoRule(
        id="PROTO-IPSEC-001",
        pattern=re.compile(r"\b(ikev1|3des-sha1|modp1024|modp768|esp=3des)\b", re.IGNORECASE),
        title="Weak IPsec / IKEv1 phase 1/2 configuration",
        category=Category.CLASSICAL_CRYPTO_WEAKNESS,
        severity=Severity.HIGH,
        description="IPsec configuration uses deprecated IKEv1 or weak DH group (MODP-1024/768).",
        cwe_id="CWE-327",
        nist_pqc_recommendation="IKEv2 with RFC 9370 Quantum-Resistant PQC extensions",
        quantum_harvest_now_risk=True,
        remediation="Upgrade to IKEv2 with AES-256-GCM and MODP-3072+ / ECP-384, preparing for RFC 9370 hybrid PQC.",
        artifact_type=ArtifactType.PROTOCOL,
    ),
    CryptoRule(
        id="PROTO-MTLS-001",
        pattern=re.compile(r"\b(ssl_verify_client\s+optional|verify_mode\s*=\s*ssl\.CERT_NONE|InsecureSkipVerify:\s*true)\b"),
        title="Insecure mTLS / Client Certificate Verification disabled",
        category=Category.AUTH_WEAKNESS,
        severity=Severity.CRITICAL,
        description="Client certificate verification is disabled or marked optional, breaking mutual TLS trust.",
        cwe_id="CWE-295",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Require valid client certificates signed by internal trusted CA.",
        artifact_type=ArtifactType.PROTOCOL,
    ),
    CryptoRule(
        id="AUTH-JWT-001",
        pattern=re.compile(r"algorithms?\s*[:=]\s*\[?[\"']none[\"']|alg[\"']?\s*:\s*[\"']none[\"']"),
        title="JWT configured to accept 'none' algorithm",
        category=Category.AUTH_WEAKNESS,
        severity=Severity.CRITICAL,
        description="Accepting JWT 'none' allows attackers to forge unsigned tokens and bypass authentication.",
        cwe_id="CWE-347",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Explicitly whitelist strong algorithms (e.g. ['ES256', 'RS256']) and never allow 'none'.",
        artifact_type=ArtifactType.PROTOCOL,
    ),
    CryptoRule(
        id="PROTO-VPN-001",
        pattern=re.compile(r"\b(cipher\s+BF-CBC|auth\s+SHA1|proto\s+pptp)\b", re.IGNORECASE),
        title="Legacy VPN cipher / protocol configuration (Blowfish/PPTP)",
        category=Category.CLASSICAL_CRYPTO_WEAKNESS,
        severity=Severity.HIGH,
        description="VPN configuration specifies broken Blowfish (SWEET32) or vulnerable PPTP protocol.",
        cwe_id="CWE-327",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Upgrade OpenVPN to AES-256-GCM or migrate to WireGuard.",
        artifact_type=ArtifactType.PROTOCOL,
    ),
]

SECRET_RULES: list[CryptoRule] = [
    CryptoRule(
        id="SEC-AWS-001",
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        title="Hardcoded AWS Access Key ID",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        description="Committed AWS access credentials allow cloud account takeover.",
        cwe_id="CWE-798",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Revoke key immediately in AWS IAM and load credentials via IAM roles or AWS Secrets Manager.",
        artifact_type=ArtifactType.RELATED_MATERIAL,
    ),
    CryptoRule(
        id="SEC-GOOGLE-001",
        pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        title="Hardcoded Google Cloud / Firebase API Key",
        category=Category.SECRET,
        severity=Severity.HIGH,
        description="A Google Cloud/Firebase API key was found hardcoded in source.",
        cwe_id="CWE-798",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Rotate key in Google Cloud Console, restrict permissions, and store in environment secrets.",
        artifact_type=ArtifactType.RELATED_MATERIAL,
    ),
    CryptoRule(
        id="SEC-AZURE-001",
        pattern=re.compile(r"(?i)\bDefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{20,}"),
        title="Hardcoded Azure Storage connection string",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        description="Full Azure Storage connection string including account key committed to source.",
        cwe_id="CWE-798",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Rotate key immediately and use Managed Identity or Azure Key Vault.",
        artifact_type=ArtifactType.RELATED_MATERIAL,
    ),
    CryptoRule(
        id="SEC-PRIVKEY-001",
        pattern=re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        title="Private key material committed to repository",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        description="PEM-encoded private key committed to repository. Anyone with git access can impersonate the key holder.",
        cwe_id="CWE-321",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Rotate key pair, purge from git history (git filter-repo), and store in HSM/KMS.",
        artifact_type=ArtifactType.RELATED_MATERIAL,
    ),
    CryptoRule(
        id="SEC-GENERIC-001",
        pattern=re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|password)\s*[:=]\s*[\"'][A-Za-z0-9_\-\.]{12,}[\"']"),
        title="Likely hardcoded credential or API key",
        category=Category.SECRET,
        severity=Severity.HIGH,
        description="Variable assignment matching credential patterns contains inline literal secret.",
        cwe_id="CWE-798",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Move to environment variables or dedicated secret store.",
        artifact_type=ArtifactType.RELATED_MATERIAL,
    ),
]

ALL_RULES = RULES + SECRET_RULES
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".cs",
    ".yml", ".yaml", ".json", ".env", ".pem", ".conf", ".cfg", ".toml", ".rs",
    ".properties", ".xml", ".gradle", ".kts", ".sh", ".bash", ".dockerfile"
}


def scan_file(file_path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = file_path.read_text(errors="ignore")
    except (OSError, UnicodeDecodeError):
        return findings

    lines = text.splitlines()
    rel_path = str(file_path.relative_to(root))

    for rule in ALL_RULES:
        for match in rule.pattern.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
            if rule.category == Category.SECRET:
                snippet = re.sub(re.escape(match.group(0)), "[REDACTED]", snippet)

            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    category=rule.category,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    file_path=rel_path,
                    line_number=line_no,
                    code_snippet=snippet[:200],
                    matched_pattern=rule.id,
                    cwe_id=rule.cwe_id,
                    nist_pqc_recommendation=rule.nist_pqc_recommendation,
                    quantum_harvest_now_risk=rule.quantum_harvest_now_risk,
                    remediation=rule.remediation,
                    artifact_type=rule.artifact_type,
                    extra={
                        "detection_method": "static pattern analysis",
                        "rule_id": rule.id,
                    },
                )
            )
    return findings


def scan_directory(root_path: str) -> tuple[list[Finding], int]:
    root = Path(root_path)
    findings: list[Finding] = []
    files_scanned = 0
    ignore_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".next", ".cargo"}

    for file_path in root.rglob("*"):
        if not file_path.is_file() or any(part in ignore_dirs for part in file_path.parts):
            continue
        if file_path.suffix.lower() not in SCANNABLE_EXTENSIONS and file_path.name.lower() not in ("dockerfile", "makefile"):
            continue
        files_scanned += 1
        findings.extend(scan_file(file_path, root))

    return findings, files_scanned
