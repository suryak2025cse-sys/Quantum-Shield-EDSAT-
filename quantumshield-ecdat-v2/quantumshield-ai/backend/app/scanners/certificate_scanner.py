"""
Certificate Scanner
=====================
Parses X.509 certificates found in the scanned project (PEM or DER encoded)
using the `cryptography` library — actual ASN.1 parsing, not a regex guess.
For each certificate, extracts the signature algorithm, public key algorithm
and size, and validity period, then flags:

  - Weak signature algorithms (MD5, SHA-1 signed certs)
  - Quantum-vulnerable public key algorithms (RSA, EC)
  - Weak RSA key sizes (< 2048 bits)
  - Expired certificates
  - Certificates expiring soon (< 90 days) — operationally relevant even
    though it isn't a cryptographic weakness per se
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.exceptions import InvalidSignature  # noqa: F401 (re-exported for callers)

from app.models.schemas import ArtifactType, Category, Finding, Severity

CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".cert"}
PEM_CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)

WEAK_SIG_HASHES = {"md5", "sha1"}


def _severity_for_cert(weak_sig: bool, weak_key: bool, expired: bool) -> Severity:
    if expired or weak_sig:
        return Severity.HIGH
    if weak_key:
        return Severity.MEDIUM
    return Severity.INFO


def _parse_cert_bytes(cert_bytes: bytes, file_path: str, root: Path) -> Finding | None:
    try:
        cert = x509.load_pem_x509_certificate(cert_bytes)
    except ValueError:
        try:
            cert = x509.load_der_x509_certificate(cert_bytes)
        except ValueError:
            return None  # not a parseable certificate

    pub_key = cert.public_key()
    now = datetime.now(timezone.utc)

    not_after = cert.not_valid_after_utc
    expired = not_after < now
    days_to_expiry = (not_after - now).days

    sig_algo_name = cert.signature_hash_algorithm.name.lower() if cert.signature_hash_algorithm else "unknown"
    weak_sig = sig_algo_name in WEAK_SIG_HASHES

    quantum_vulnerable = False
    weak_key = False
    key_algo = "unknown"
    key_size = None

    if isinstance(pub_key, rsa.RSAPublicKey):
        key_algo = "RSA"
        key_size = pub_key.key_size
        quantum_vulnerable = True
        weak_key = key_size < 2048
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_algo = f"ECDSA ({pub_key.curve.name})"
        key_size = pub_key.curve.key_size
        quantum_vulnerable = True
    else:
        key_algo = type(pub_key).__name__

    issues = []
    if weak_sig:
        issues.append(f"signed with weak {sig_algo_name.upper()} hash")
    if weak_key:
        issues.append(f"RSA key size {key_size} bits is below the 2048-bit minimum")
    if expired:
        issues.append(f"expired {abs(days_to_expiry)} days ago")
    elif days_to_expiry < 90:
        issues.append(f"expires in {days_to_expiry} days")
    if quantum_vulnerable:
        issues.append(f"public key algorithm ({key_algo}) is quantum-vulnerable")

    severity = _severity_for_cert(weak_sig, weak_key, expired)
    subject = cert.subject.rfc4514_string()

    title = f"Certificate issue: {key_algo}, {sig_algo_name.upper()} signature"
    description = (
        f"Certificate for '{subject}' " + (", ".join(issues) if issues else "has no immediate issues") + "."
    )

    return Finding(
        id=str(uuid.uuid4()),
        category=Category.CERTIFICATE_ISSUE,
        severity=severity,
        title=title,
        description=description,
        file_path=str(Path(file_path)),
        matched_pattern="CERT-X509-001",
        cwe_id="CWE-295" if (weak_sig or expired) else None,
        nist_pqc_recommendation="ML-DSA (FIPS 204) certificate signing, once CA/browser support lands" if quantum_vulnerable else None,
        quantum_harvest_now_risk=quantum_vulnerable,
        remediation=(
            "Reissue with a 2048+/3072+ bit RSA key or migrate to ECDSA P-256+, using SHA-256 signatures at minimum; "
            "plan for hybrid/PQC certificate support as CA tooling matures."
        ),
        artifact_type=ArtifactType.CERTIFICATE,
        extra={
            "subject": subject,
            "issuer": cert.issuer.rfc4514_string(),
            "not_valid_after": not_after.isoformat(),
            "signature_algorithm": sig_algo_name,
            "public_key_algorithm": key_algo,
            "key_size_bits": key_size,
            "expired": expired,
            "days_to_expiry": days_to_expiry,
        },
    )


def scan_certificates(root_path: str) -> list[Finding]:
    root = Path(root_path)
    findings: list[Finding] = []
    ignore_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}

    for file_path in root.rglob("*"):
        if not file_path.is_file() or any(part in ignore_dirs for part in file_path.parts):
            continue

        try:
            raw = file_path.read_bytes()
        except OSError:
            continue

        # Extract every PEM certificate block in the file (a bundle may have several)
        pem_blocks = PEM_CERT_RE.findall(raw)
        if pem_blocks:
            for block in pem_blocks:
                finding = _parse_cert_bytes(block, str(file_path.relative_to(root)), root)
                if finding:
                    findings.append(finding)
        elif file_path.suffix.lower() in CERT_EXTENSIONS:
            # No PEM markers found but the extension suggests DER encoding — try that.
            finding = _parse_cert_bytes(raw, str(file_path.relative_to(root)), root)
            if finding:
                findings.append(finding)

    return findings
