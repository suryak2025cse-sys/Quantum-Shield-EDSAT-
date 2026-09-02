"""
Cryptography & Quantum-Readiness Scanner
==========================================
This is the flagship detector. It performs static analysis over source files
to build a lightweight "Cryptographic Bill of Materials" (CBOM) — identifying
every cryptographic primitive in use — then flags anything that is:

  (a) classically weak today (MD5, SHA1, RC4, ECB mode, weak TLS versions)
  (b) "quantum-vulnerable": broken by Shor's algorithm on a sufficiently large
      fault-tolerant quantum computer (RSA, ECC/ECDSA/ECDH, classic Diffie-Hellman)

Design note: we do NOT attempt to run an actual quantum circuit simulation
against target crypto (that's a research exercise, not what a scanning
product does). Real CBOM tools — including IBM's own PQC risk assessment
tooling and the Linux Foundation's PQCA — work exactly this way: static
pattern/AST matching against known-weak primitive names and API calls,
mapped to a migration recommendation (NIST FIPS 203/204/205). We follow
that same real-world approach here.
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


# ---------------------------------------------------------------------------
# Rule set. Patterns target common usage across Python (cryptography, pycrypto,
# pyca), Java (JCE), Node (crypto/node-forge), and Go (crypto/*) idioms, plus
# raw algorithm-name references in config/certs (OpenSSL, PEM headers).
# ---------------------------------------------------------------------------
RULES: list[CryptoRule] = [
    CryptoRule(
        id="QC-RSA-001",
        pattern=re.compile(r"\b(RSA\.generate|rsa\.generate_private_key|RSA_generate_key|new\s+RSACryptoServiceProvider|RSAKeyGenParameterSpec|Crypto\.PublicKey\.RSA|RS256|RS384|RS512)\b"),
        title="RSA key generation / RSA-based signing detected",
        category=Category.QUANTUM_VULNERABLE_CRYPTO,
        severity=Severity.HIGH,
        description="RSA relies on the hardness of integer factorization, which Shor's algorithm solves in polynomial time on a fault-tolerant quantum computer. Any RSA-protected data or long-lived signature is at risk once cryptographically relevant quantum computers (CRQCs) exist.",
        cwe_id="CWE-327",
        nist_pqc_recommendation="ML-KEM (FIPS 203) for key exchange, ML-DSA (FIPS 204) for signatures",
        quantum_harvest_now_risk=True,
        remediation="Plan migration to a hybrid classical+PQC scheme (e.g. X25519+ML-KEM) for key exchange, and ML-DSA or SLH-DSA for signatures. Prioritize by data sensitivity lifetime.",
    ),
    CryptoRule(
        id="QC-ECC-001",
        pattern=re.compile(r"\b(ec\.generate_private_key|ECDSA|ECDH|SECP256R1|SECP384R1|SECP521R1|prime256v1|secp256k1|ES256|ES384|ES512|EllipticCurve)\b"),
        title="Elliptic-curve cryptography (ECC/ECDSA/ECDH) detected",
        category=Category.QUANTUM_VULNERABLE_CRYPTO,
        severity=Severity.HIGH,
        description="ECC-based schemes (ECDSA, ECDH, and curve-based signatures like ES256) rely on the elliptic-curve discrete log problem, which is also broken by Shor's algorithm — and with a smaller quantum resource requirement than RSA of equivalent classical strength.",
        cwe_id="CWE-327",
        nist_pqc_recommendation="ML-KEM (FIPS 203) for exchange, ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures",
        quantum_harvest_now_risk=True,
        remediation="Use hybrid key exchange (e.g. X25519+ML-KEM768) during the transition period; migrate signature schemes to ML-DSA where standards support it (e.g. updated TLS 1.3 ciphersuites, JWT 'alg' extensions).",
    ),
    CryptoRule(
        id="QC-DH-001",
        pattern=re.compile(r"\b(Diffie[-_]?Hellman|DHParameterSpec|dhparam|DHE_RSA|DH_anon)\b"),
        title="Classic (finite-field) Diffie-Hellman key exchange detected",
        category=Category.QUANTUM_VULNERABLE_CRYPTO,
        severity=Severity.HIGH,
        description="Finite-field Diffie-Hellman is vulnerable to Shor's algorithm for discrete logarithms, exposing forward secrecy of any session using it once CRQCs exist.",
        cwe_id="CWE-327",
        nist_pqc_recommendation="ML-KEM (FIPS 203) hybrid key exchange",
        quantum_harvest_now_risk=True,
        remediation="Replace with hybrid PQC key encapsulation (ML-KEM) combined with X25519 for defense-in-depth during standards transition.",
    ),
    CryptoRule(
        id="CS-SHA1-001",
        pattern=re.compile(r"\b(SHA1|SHA-1|sha1\(|hashlib\.sha1|MessageDigest\.getInstance\([\"']SHA-1[\"']\))\b"),
        title="SHA-1 hash function in use",
        category=Category.CLASSICAL_CRYPTO_WEAKNESS,
        severity=Severity.MEDIUM,
        description="SHA-1 has known practical collision attacks (SHAttered, 2017) and is deprecated by NIST for digital signatures and certificate signing.",
        cwe_id="CWE-328",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Replace with SHA-256 or SHA-3. This is a classical (non-quantum) weakness and should be prioritized immediately regardless of quantum timeline.",
    ),
    CryptoRule(
        id="CS-MD5-001",
        pattern=re.compile(r"\b(MD5|md5\(|hashlib\.md5|MessageDigest\.getInstance\([\"']MD5[\"']\))\b"),
        title="MD5 hash function in use",
        category=Category.CLASSICAL_CRYPTO_WEAKNESS,
        severity=Severity.HIGH,
        description="MD5 is cryptographically broken; collisions can be generated trivially. It must never be used for signatures, certificates, or integrity checks.",
        cwe_id="CWE-328",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Replace with SHA-256/SHA-3 for integrity, or a proper password hashing function (Argon2id, bcrypt, scrypt) for credentials.",
    ),
    CryptoRule(
        id="CS-DES-001",
        pattern=re.compile(r"\b(DES|3DES|TripleDES|RC4|ARC4)\b"),
        title="Legacy weak symmetric cipher (DES/3DES/RC4) detected",
        category=Category.CLASSICAL_CRYPTO_WEAKNESS,
        severity=Severity.HIGH,
        description="DES (56-bit) and RC4 are broken by classical brute-force/statistical attacks; 3DES is deprecated (NIST SP 800-131A) due to meet-in-the-middle attacks and small block size (Sweet32).",
        cwe_id="CWE-327",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Migrate to AES-256-GCM or ChaCha20-Poly1305. Note: symmetric AES-256 is considered quantum-resistant against Grover's algorithm at this key length and does not need PQC migration.",
    ),
    CryptoRule(
        id="CS-ECB-001",
        pattern=re.compile(r"\bAES\.MODE_ECB\b|Cipher\.getInstance\([\"']AES/ECB"),
        title="AES used in insecure ECB mode",
        category=Category.CLASSICAL_CRYPTO_WEAKNESS,
        severity=Severity.HIGH,
        description="ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, leaking structural patterns (the classic 'ECB penguin' problem).",
        cwe_id="CWE-327",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Use AES-GCM (authenticated encryption) instead of ECB or unauthenticated CBC.",
    ),
    CryptoRule(
        id="CS-TLS-001",
        pattern=re.compile(r"\b(TLSv1\.0|TLSv1\.1|SSLv2|SSLv3|PROTOCOL_TLSv1\b|PROTOCOL_SSLv3)\b"),
        title="Legacy TLS/SSL protocol version allowed",
        category=Category.CLASSICAL_CRYPTO_WEAKNESS,
        severity=Severity.HIGH,
        description="TLS 1.0/1.1 and all SSL versions are deprecated (RFC 8996) due to known protocol-level vulnerabilities (BEAST, POODLE, etc.).",
        cwe_id="CWE-326",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Enforce TLS 1.3 minimum (TLS 1.2 as floor only when required for legacy client compatibility).",
    ),
    CryptoRule(
        id="AUTH-JWT-001",
        pattern=re.compile(r"algorithms?\s*[:=]\s*\[?[\"']none[\"']|alg[\"']?\s*:\s*[\"']none[\"']"),
        title="JWT configured to accept 'none' algorithm",
        category=Category.AUTH_WEAKNESS,
        severity=Severity.CRITICAL,
        description="Accepting the JWT 'none' algorithm allows attackers to forge unsigned tokens that bypass authentication entirely.",
        cwe_id="CWE-347",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Explicitly whitelist strong algorithms (e.g. ['RS256'] or ['ES256']) and never allow 'none' in the verification allow-list.",
    ),
]

SECRET_RULES: list[CryptoRule] = [
    CryptoRule(
        id="SEC-AWS-001",
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        title="Hardcoded AWS Access Key ID",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        description="A hardcoded AWS access key was found in source. Committed AWS credentials are one of the most common causes of cloud account takeover and cryptomining abuse.",
        cwe_id="CWE-798",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Revoke this key immediately in the AWS IAM console, then move to environment variables or a secrets manager (AWS Secrets Manager / Vault). Add the pattern to a pre-commit secrets scanner.",
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
        remediation="Rotate the key in Google Cloud Console, restrict it by API/referrer, and load it from environment configuration instead.",
    ),
    CryptoRule(
        id="SEC-AZURE-001",
        pattern=re.compile(r"(?i)\bDefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{20,}"),
        title="Hardcoded Azure Storage connection string",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        description="A full Azure Storage account connection string, including the account key, was found in source.",
        cwe_id="CWE-798",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Rotate the storage account key immediately and switch to Managed Identity or Azure Key Vault references.",
    ),
    CryptoRule(
        id="SEC-PRIVKEY-001",
        pattern=re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        title="Private key material committed to repository",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        description="A PEM-encoded private key block was found in the codebase. This is a critical exposure — anyone with repo access (including in git history) can impersonate the key holder.",
        cwe_id="CWE-321",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Rotate the key pair, purge it from git history (git filter-repo / BFG), and store keys in a secrets manager or KMS/HSM instead of the repo.",
    ),
    CryptoRule(
        id="SEC-GENERIC-001",
        pattern=re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|password)\s*[:=]\s*[\"'][A-Za-z0-9_\-\.]{12,}[\"']"),
        title="Likely hardcoded credential or API key",
        category=Category.SECRET,
        severity=Severity.HIGH,
        description="A variable assignment matching common credential-naming patterns was found with an inline literal value, suggesting a hardcoded secret.",
        cwe_id="CWE-798",
        nist_pqc_recommendation=None,
        quantum_harvest_now_risk=False,
        remediation="Move to environment variables, a .env file excluded via .gitignore, or a secrets manager. Add gitleaks/truffleHog to CI to prevent recurrence.",
    ),
]

ALL_RULES = RULES + SECRET_RULES

SCANNABLE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".yml", ".yaml", ".json", ".env", ".pem", ".conf", ".cfg", ".toml"}

# Maps a finding's Category to the CBOM-standard artifact type (CycloneDX
# cryptoProperties.assetType). Secrets/keys are "related-material", TLS/JWT
# config issues are "protocol", everything else defaults to "algorithm".
_ARTIFACT_TYPE_BY_CATEGORY = {
    Category.SECRET: ArtifactType.RELATED_MATERIAL,
    Category.AUTH_WEAKNESS: ArtifactType.PROTOCOL,
}


def scan_file(file_path: Path, root: Path) -> list[Finding]:
    """Scan a single file against all crypto + secret rules, return Findings."""
    findings: list[Finding] = []
    try:
        text = file_path.read_text(errors="ignore")
    except (OSError, UnicodeDecodeError):
        return findings

    lines = text.splitlines()
    rel_path = str(file_path.relative_to(root))

    for rule in ALL_RULES:
        for match in rule.pattern.finditer(text):
            # Determine line number from character offset
            line_no = text.count("\n", 0, match.start()) + 1
            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
            # Redact secret values in the snippet before it's ever stored/displayed
            if rule.category == Category.SECRET:
                snippet = re.sub(re.escape(match.group(0)), "«REDACTED»", snippet)

            artifact_type = _ARTIFACT_TYPE_BY_CATEGORY.get(rule.category, ArtifactType.ALGORITHM)
            # TLS version findings are a protocol issue, not an "algorithm" per se
            if rule.id == "CS-TLS-001":
                artifact_type = ArtifactType.PROTOCOL

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
                    artifact_type=artifact_type,
                )
            )
    return findings


def scan_directory(root_path: str) -> tuple[list[Finding], int]:
    """Walk a directory tree and scan every scannable file. Returns (findings, files_scanned)."""
    root = Path(root_path)
    findings: list[Finding] = []
    files_scanned = 0

    ignore_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".next"}

    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        if any(part in ignore_dirs for part in file_path.parts):
            continue
        if file_path.suffix.lower() not in SCANNABLE_EXTENSIONS:
            continue
        files_scanned += 1
        findings.extend(scan_file(file_path, root))

    return findings, files_scanned
