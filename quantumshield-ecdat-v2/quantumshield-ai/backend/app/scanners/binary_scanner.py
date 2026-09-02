"""
Binary Artifact Scanner
==========================
Full binary disassembly to extract cryptographic call graphs is out of scope
for a static source scanner — that's a distinct, much heavier engineering
problem (symbol resolution, control-flow analysis across architectures).
What's genuinely achievable and still useful: extracting printable ASCII
strings from compiled binaries (.so, .dll, .exe, .dylib, .a) and matching
them against known crypto-library version banners and algorithm identifiers
that compilers/linkers routinely embed as literal strings (e.g. OpenSSL
embeds "OpenSSL 1.0.2k" style banners; many TLS libraries embed cipher suite
name tables in cleartext).

This is the same "strings | grep" technique real-world binary auditing
starts with — it's a legitimate, well-understood first pass, not a
full binary CBOM. It will miss anything stripped or obfuscated; it's
presented here as a first-pass triage step, not a definitive analysis.
"""
from __future__ import annotations

import re
import uuid
from pathlib import Path

from app.models.schemas import ArtifactType, Category, Finding, Severity

BINARY_EXTENSIONS = {".so", ".dll", ".exe", ".dylib", ".a", ".lib"}
IGNORE_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}

MIN_STRING_LEN = 4
PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)

# version-banner patterns known to be embedded literally by common crypto libs
VERSION_BANNER_RULES = [
    (re.compile(rb"OpenSSL (0\.9|1\.0)\.[\d\w.]*"), "OpenSSL 0.9.x/1.0.x", Severity.HIGH,
     "OpenSSL 0.9.x and 1.0.x reached end-of-life years ago and no longer receive security patches (Heartbleed-era and later CVEs affect these lines)."),
    (re.compile(rb"OpenSSL 1\.1\.[\d\w.]*"), "OpenSSL 1.1.x", Severity.MEDIUM,
     "OpenSSL 1.1.x reached end-of-life in September 2023. Upgrade to 3.x for continued security patches and post-quantum algorithm support (OpenSSL 3.5+)."),
    (re.compile(rb"OpenSSL 3\.[\d\w.]*"), "OpenSSL 3.x", Severity.INFO,
     "OpenSSL 3.x is current; 3.5+ adds ML-KEM support."),
    (re.compile(rb"libcrypto\.so\.1\.0"), "libcrypto 1.0 (linked)", Severity.HIGH,
     "Binary links against libcrypto 1.0, an end-of-life OpenSSL major version."),
]

ALGO_IDENTIFIER_RULES = [
    (re.compile(rb"\bRSA_generate_key\b"), "RSA key generation symbol", "RSA"),
    (re.compile(rb"\bEC_KEY_new\b"), "EC key generation symbol", "ECC"),
    (re.compile(rb"\bMD5_Init\b"), "MD5 symbol", "MD5"),
    (re.compile(rb"\bSHA1_Init\b"), "SHA-1 symbol", "SHA-1"),
    (re.compile(rb"\bDES_encrypt\b"), "DES symbol", "DES"),
]


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

        for pattern, label, severity, description in VERSION_BANNER_RULES:
            m = pattern.search(raw)
            if m:
                banner = m.group(0).decode(errors="replace")
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        category=Category.BINARY_ARTIFACT,
                        severity=severity,
                        title=f"Embedded version banner: {banner}",
                        description=f"Found via strings-based scan of the compiled binary. {description}",
                        file_path=rel,
                        matched_pattern="BIN-BANNER-001",
                        artifact_type=ArtifactType.LIBRARY,
                        remediation="Rebuild/relink against a current, supported version of this library.",
                        extra={"detection_method": "strings-based binary scan", "banner": banner, "library": label},
                    )
                )
                break  # one banner match per file is enough signal

        found_algos = set()
        for pattern, label, algo in ALGO_IDENTIFIER_RULES:
            if algo in found_algos:
                continue
            if pattern.search(raw):
                found_algos.add(algo)
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        category=Category.BINARY_ARTIFACT,
                        severity=Severity.LOW,
                        title=f"{label} found in compiled binary",
                        description=(
                            f"A symbol/string matching {label} was found via strings-based scanning. "
                            "This indicates the algorithm is likely linked into the binary, though not "
                            "necessarily actively called at runtime — treat as a lead for manual verification."
                        ),
                        file_path=rel,
                        matched_pattern="BIN-ALGO-001",
                        artifact_type=ArtifactType.ALGORITHM,
                        quantum_harvest_now_risk=algo in ("RSA", "ECC"),
                        extra={"detection_method": "strings-based binary scan", "algorithm": algo},
                    )
                )

    return findings
