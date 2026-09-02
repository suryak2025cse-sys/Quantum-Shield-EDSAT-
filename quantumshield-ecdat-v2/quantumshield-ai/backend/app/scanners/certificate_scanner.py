"""
Certificate Scanner
=====================
Deep X.509 certificate parser (PEM and DER encoded) using cryptography library.
Extracts comprehensive PKI metadata, Subject Alternative Names (SANs), serial numbers,
validity windows, signature hashing, key sizes, self-signed status, and CA constraints.

Flags:
  - Weak signature algorithms (MD5, SHA-1 signed certs)
  - Quantum-vulnerable public key algorithms (RSA, ECDSA/ECC)
  - Weak RSA key sizes (< 2048 bits)
  - Expired and expiring-soon (< 90 days) certificates
  - Self-signed certificates in production paths
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, ed25519, ed448

from app.models.schemas import ArtifactType, Category, Finding, Severity

CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".cert", ".der"}
PEM_CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)

WEAK_SIG_HASHES = {"md5", "sha1", "sha-1"}


def _severity_for_cert(weak_sig: bool, weak_key: bool, expired: bool, days_to_expiry: int) -> Severity:
    if expired or weak_sig:
        return Severity.HIGH
    if weak_key or days_to_expiry < 30:
        return Severity.HIGH
    if days_to_expiry < 90:
        return Severity.MEDIUM
    return Severity.INFO


def _parse_cert_bytes(cert_bytes: bytes, file_path: str, format_type: str = "PEM") -> Finding | None:
    try:
        if format_type == "PEM":
            cert = x509.load_pem_x509_certificate(cert_bytes)
        else:
            cert = x509.load_der_x509_certificate(cert_bytes)
    except Exception:
        try:
            cert = x509.load_der_x509_certificate(cert_bytes)
            format_type = "DER"
        except Exception:
            return None

    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    expired = not_after < now
    days_to_expiry = (not_after - now).days

    pub_key = cert.public_key()
    quantum_vulnerable = False
    weak_key = False
    key_algo = "Unknown"
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
    elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key_algo = type(pub_key).__name__.replace("PublicKey", "")
        key_size = 256 if "25519" in key_algo else 448
        quantum_vulnerable = True
    elif isinstance(pub_key, dsa.DSAPublicKey):
        key_algo = "DSA"
        key_size = pub_key.key_size
        quantum_vulnerable = True
        weak_key = True
    else:
        key_algo = type(pub_key).__name__

    sig_algo_name = cert.signature_hash_algorithm.name.lower() if cert.signature_hash_algorithm else "unknown"
    weak_sig = sig_algo_name in WEAK_SIG_HASHES

    subject_str = cert.subject.rfc4514_string()
    issuer_str = cert.issuer.rfc4514_string()
    is_self_signed = subject_str == issuer_str
    serial_hex = f"{cert.serial_number:X}"

    san_entries: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
        san_entries = [str(name.value) for name in san_ext.value]
    except x509.ExtensionNotFound:
        pass

    is_ca = False
    try:
        bc_ext = cert.extensions.get_extension_for_oid(x509.OID_BASIC_CONSTRAINTS)
        is_ca = bc_ext.value.ca
    except x509.ExtensionNotFound:
        pass

    issues = []
    if weak_sig:
        issues.append(f"signed with deprecated {sig_algo_name.upper()} signature hash")
    if weak_key:
        issues.append(f"{key_algo} key size ({key_size} bits) is below secure baseline")
    if expired:
        issues.append(f"expired {abs(days_to_expiry)} days ago ({not_after.strftime('%Y-%m-%d')})")
    elif days_to_expiry < 90:
        issues.append(f"expires in {days_to_expiry} days ({not_after.strftime('%Y-%m-%d')})")
    if is_self_signed:
        issues.append("self-signed root certificate")
    if quantum_vulnerable:
        issues.append(f"public key algorithm ({key_algo}) is quantum-vulnerable to Shor's algorithm")

    severity = _severity_for_cert(weak_sig, weak_key, expired, days_to_expiry)
    if not issues:
        issues.append("valid X.509 certificate")

    title = f"Certificate issue: {key_algo}, {sig_algo_name.upper()} signature"
    description = (
        f"X.509 Certificate ({format_type}) for '{subject_str}' "
        f"issued by '{issuer_str}'. Issues: {', '.join(issues)}."
    )

    expiry_status = "expired" if expired else ("expiring_soon" if days_to_expiry < 90 else "valid")

    return Finding(
        id=str(uuid.uuid4()),
        category=Category.CERTIFICATE_ISSUE,
        severity=severity,
        title=title,
        description=description,
        file_path=str(Path(file_path)),
        matched_pattern="CERT-X509-001",
        cwe_id="CWE-295" if (weak_sig or expired or weak_key) else None,
        nist_pqc_recommendation=(
            "Migrate PKI to dual-signature certificates supporting ML-DSA (FIPS 204) / SLH-DSA (FIPS 205)"
            if quantum_vulnerable else None
        ),
        quantum_harvest_now_risk=quantum_vulnerable,
        remediation=(
            "Reissue with minimum 2048/3072-bit RSA or ECDSA P-256 using SHA-256+ signatures. "
            "Plan for dual-signature hybrid/PQC certificates for long-term PKI validity."
        ),
        artifact_type=ArtifactType.CERTIFICATE,
        extra={
            "certificate_format": format_type,
            "subject": subject_str,
            "issuer": issuer_str,
            "serial_number": serial_hex,
            "not_valid_before": not_before.isoformat(),
            "not_valid_after": not_after.isoformat(),
            "public_key_algorithm": key_algo,
            "key_size_bits": key_size,
            "signature_algorithm": sig_algo_name,
            "san_entries": san_entries,
            "is_self_signed": is_self_signed,
            "is_ca": is_ca,
            "expired": expired,
            "days_to_expiry": days_to_expiry,
            "expiry_status": expiry_status,
            "note": "Static certificate discovery. Live endpoint TLS scanning is a planned roadmap extension.",
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

        rel_path = str(file_path.relative_to(root))

        pem_blocks = PEM_CERT_RE.findall(raw)
        if pem_blocks:
            for block in pem_blocks:
                f = _parse_cert_bytes(block, rel_path, format_type="PEM")
                if f:
                    findings.append(f)
        elif file_path.suffix.lower() in CERT_EXTENSIONS:
            f = _parse_cert_bytes(raw, rel_path, format_type="DER" if file_path.suffix.lower() == ".der" else "PEM")
            if f:
                findings.append(f)

    return findings
