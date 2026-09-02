"""
Binary Artifact Scanner
=========================
Static string and header analysis for compiled binary artifacts (.so, .dll, .exe, .dylib, .a).

Extracts:
  - Binary format (ELF, PE, Mach-O) and target architecture (x86_64, aarch64, arm)
  - Embedded version banners (OpenSSL, WolfSSL, MbedTLS, BoringSSL)
  - Static cryptographic symbols and algorithm signatures

Label: First-pass static binary analysis (Inferred Heuristic).
"""
from __future__ import annotations

import re
import struct
import uuid
from pathlib import Path

from app.models.schemas import ArtifactType, Category, Finding, Severity

BINARY_EXTENSIONS = {".so", ".dll", ".exe", ".dylib", ".a", ".lib", ".node", ".dylib"}
IGNORE_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}

VERSION_BANNER_RULES = [
    (re.compile(rb"OpenSSL (0\.9|1\.0)\.[\d\w.]*"), "OpenSSL 0.9.x/1.0.x", Severity.HIGH,
     "OpenSSL 0.9.x/1.0.x reached end-of-life and contains known unpatched CVEs."),
    (re.compile(rb"OpenSSL 1\.1\.[\d\w.]*"), "OpenSSL 1.1.x", Severity.MEDIUM,
     "OpenSSL 1.1.x reached end-of-life in September 2023. Upgrade to OpenSSL 3.x for PQC readiness."),
    (re.compile(rb"OpenSSL 3\.[\d\w.]*"), "OpenSSL 3.x", Severity.INFO,
     "OpenSSL 3.x is actively maintained (v3.5+ supports NIST ML-KEM)."),
    (re.compile(rb"wolfSSL ([0-9]+\.[0-9]+\.[0-9]+)"), "WolfSSL", Severity.INFO,
     "WolfSSL embedded SSL/TLS library detected."),
    (re.compile(rb"mbed TLS ([0-9]+\.[0-9]+\.[0-9]+)"), "MbedTLS", Severity.INFO,
     "MbedTLS / PolarSSL lightweight cryptographic library detected."),
    (re.compile(rb"libcrypto\.so\.1\.0"), "libcrypto 1.0 (linked)", Severity.HIGH,
     "Binary dynamically links against deprecated libcrypto 1.0."),
]

ALGO_IDENTIFIER_RULES = [
    (re.compile(rb"\bRSA_generate_key\b|\bRSA_new\b"), "RSA key generation symbol", "RSA", True),
    (re.compile(rb"\bEC_KEY_new\b|\bECDSA_do_sign\b"), "EC key generation symbol", "ECC", True),
    (re.compile(rb"\bDH_generate_key\b|\bDH_new\b"), "Diffie-Hellman symbol", "DH", True),
    (re.compile(rb"\bMD5_Init\b|\bMD5_Update\b"), "MD5 symbol", "MD5", False),
    (re.compile(rb"\bSHA1_Init\b|\bSHA1_Update\b"), "SHA-1 symbol", "SHA-1", False),
    (re.compile(rb"\bDES_encrypt\b|\bDES_ecb_encrypt\b"), "DES symbol", "DES", False),
]


def _detect_format_and_arch(raw: bytes) -> tuple[str, str | None]:
    """Detect binary container format and architecture from magic bytes."""
    if len(raw) < 20:
        return "Unknown", None

    if raw[:4] == b"\x7fELF":
        is_64 = raw[4] == 2
        machine = struct.unpack("<H" if raw[5] == 1 else ">H", raw[18:20])[0] if len(raw) >= 20 else 0
        arch_map = {0x03: "x86", 0x3E: "x86_64", 0x28: "ARM", 0xB7: "AArch64", 0xF3: "RISC-V"}
        arch = arch_map.get(machine, "64-bit" if is_64 else "32-bit")
        return "ELF (Linux)", arch

    if raw[:2] == b"MZ":
        return "PE (Windows)", "x86/x64"

    if raw[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "Mach-O (macOS)", "x86_64/ARM64"

    return "Binary", None


def scan_binaries(root_path: str) -> list[Finding]:
    root = Path(root_path)
    findings: list[Finding] = []

    for file_path in root.rglob("*"):
        if not file_path.is_file() or any(part in IGNORE_DIRS for part in file_path.parts):
            continue
        if file_path.suffix.lower() not in BINARY_EXTENSIONS:
            continue

        try:
            raw = file_path.read_bytes()
        except OSError:
            continue

        rel = str(file_path.relative_to(root))
        fmt, arch = _detect_format_and_arch(raw)
        arch_str = f" [{fmt}, {arch}]" if arch else f" [{fmt}]"

        for pattern, label, severity, description in VERSION_BANNER_RULES:
            m = pattern.search(raw)
            if m:
                banner = m.group(0).decode(errors="replace")
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        category=Category.BINARY_ARTIFACT,
                        severity=severity,
                        title=f"Embedded version banner: {banner}{arch_str}",
                        description=f"First-pass static binary scan of {rel}: {description}",
                        file_path=rel,
                        matched_pattern="BIN-BANNER-001",
                        artifact_type=ArtifactType.LIBRARY,
                        remediation="Rebuild or relink with a supported version supporting PQC standards.",
                        extra={
                            "detection_method": "strings-based binary scan",
                            "confidence": "Inferred Heuristic",
                            "banner": banner,
                            "binary_format": fmt,
                            "architecture": arch,
                            "library": label,
                        },
                    )
                )
                break

        found_algos = set()
        for pattern, label, algo, is_quantum_vuln in ALGO_IDENTIFIER_RULES:
            if algo in found_algos:
                continue
            if pattern.search(raw):
                found_algos.add(algo)
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        category=Category.BINARY_ARTIFACT,
                        severity=Severity.LOW if not is_quantum_vuln else Severity.MEDIUM,
                        title=f"{label} found in compiled binary{arch_str}",
                        description=(
                            f"Static symbol matching {label} was detected in {rel}. "
                            f"Algorithm '{algo}' is linked into the compiled binary."
                        ),
                        file_path=rel,
                        matched_pattern="BIN-ALGO-001",
                        artifact_type=ArtifactType.ALGORITHM,
                        quantum_harvest_now_risk=is_quantum_vuln,
                        nist_pqc_recommendation="Transition binary link dependencies to ML-KEM / ML-DSA" if is_quantum_vuln else None,
                        extra={
                            "detection_method": "strings-based binary scan",
                            "confidence": "Inferred Heuristic",
                            "algorithm": algo,
                            "binary_format": fmt,
                            "architecture": arch,
                        },
                    )
                )

    return findings
