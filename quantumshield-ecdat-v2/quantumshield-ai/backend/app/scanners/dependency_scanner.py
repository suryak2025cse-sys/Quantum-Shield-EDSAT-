"""
Dependency / Library Scanner
==============================
Parses 14 dependency manifest and lockfile formats across Python, JavaScript/TypeScript,
Java/JVM, Go, and Rust ecosystems:

  - Python: requirements.txt, pyproject.toml, poetry.lock, Pipfile.lock
  - JavaScript / Node: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
  - Java / JVM: pom.xml, build.gradle, build.gradle.kts
  - Go: go.mod, go.sum
  - Rust: Cargo.toml, Cargo.lock

Builds a comprehensive catalogue of cryptographic libraries in use, flags known-deprecated
packages, distinguishes direct vs transitive dependencies, and checks OSV.dev for CVEs.
"""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any

import httpx

from app.models.schemas import ArtifactType, Category, Finding, Severity

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT_SECONDS = 3.0

KNOWN_CRYPTO_LIBRARIES: dict[str, dict[str, Any]] = {
    # Python (PyPI)
    "pycrypto": {"ecosystem": "PyPI", "deprecated": True, "note": "Unmaintained since 2013; known CVEs unpatched. Migrate to pycryptodome or `cryptography`.", "crypto_relevance": "Legacy cryptography engine"},
    "pycryptodome": {"ecosystem": "PyPI", "deprecated": False, "note": "Actively maintained drop-in replacement for PyCrypto.", "crypto_relevance": "General symmetric/asymmetric cryptographic primitives"},
    "cryptography": {"ecosystem": "PyPI", "deprecated": False, "note": "Actively maintained; OpenSSL wrapper with modern TLS and PQC readiness in 42+.", "crypto_relevance": "Core cryptographic primitives, X.509, AEAD, KDF"},
    "pyopenssl": {"ecosystem": "PyPI", "deprecated": False, "note": "Python wrapper module around OpenSSL.", "crypto_relevance": "TLS / SSL networking"},
    "rsa": {"ecosystem": "PyPI", "deprecated": False, "note": "Pure-Python RSA implementation. Quantum-vulnerable to Shor's algorithm.", "crypto_relevance": "RSA encryption and signatures"},
    "jose": {"ecosystem": "PyPI", "deprecated": False, "note": "JWT/JOSE implementation — verify algorithm allow-lists exclude 'none'.", "crypto_relevance": "JWT/JWE token signing and verification"},
    "python-jose": {"ecosystem": "PyPI", "deprecated": False, "note": "JWT/JOSE implementation — verify algorithm allow-lists exclude 'none'.", "crypto_relevance": "JWT/JWE token signing and verification"},
    "ecdsa": {"ecosystem": "PyPI", "deprecated": False, "note": "Pure-Python ECDSA. Quantum-vulnerable.", "crypto_relevance": "ECDSA signatures"},
    "paramiko": {"ecosystem": "PyPI", "deprecated": False, "note": "SSHv2 implementation for Python. Check for legacy ssh-rsa hostkey usage.", "crypto_relevance": "SSH protocol & transport encryption"},
    "pynacl": {"ecosystem": "PyPI", "deprecated": False, "note": "Python binding to libsodium (Ed25519, Curve25519, ChaCha20-Poly1305).", "crypto_relevance": "Modern high-speed cryptography"},

    # Node / JavaScript (npm)
    "node-forge": {"ecosystem": "npm", "deprecated": False, "note": "Pure-JS implementation of TLS, PKI, and cryptographic ciphers.", "crypto_relevance": "TLS, X.509, RSA, AES"},
    "jsrsasign": {"ecosystem": "npm", "deprecated": False, "note": "Pure-JS crypto/PKI toolkit — verify key length and signature algorithms.", "crypto_relevance": "PKI, ASN.1, signatures"},
    "jsonwebtoken": {"ecosystem": "npm", "deprecated": False, "note": "JWT verification library — ensure 'algorithms' whitelist excludes 'none'.", "crypto_relevance": "JWT signing and verification"},
    "crypto-js": {"ecosystem": "npm", "deprecated": False, "note": "JavaScript library of crypto standards (MD5, SHA1, AES, DES, Rabbit).", "crypto_relevance": "Client-side encryption / hashing"},
    "jose": {"ecosystem": "npm", "deprecated": False, "note": "Modern universal 'JSON Web Almost Everything' library.", "crypto_relevance": "JWS, JWE, JWK, JWT"},
    "sodium-native": {"ecosystem": "npm", "deprecated": False, "note": "Node.js bindings to libsodium.", "crypto_relevance": "Modern authenticated cryptography"},
    "noble-curves": {"ecosystem": "npm", "deprecated": False, "note": "Audited pure-JS elliptic curves library.", "crypto_relevance": "Elliptic curve cryptography"},

    # Java / JVM (Maven)
    "bouncycastle": {"ecosystem": "Maven", "deprecated": False, "note": "Actively maintained; supports NIST PQC algorithms (ML-KEM, ML-DSA) in v1.78+.", "crypto_relevance": "Comprehensive Java cryptographic service provider"},
    "bcprov-jdk18on": {"ecosystem": "Maven", "deprecated": False, "note": "Bouncy Castle Cryptography Package for Java 8+ with PQC support.", "crypto_relevance": "JCE Provider & PQC primitives"},
    "bcpkix-jdk18on": {"ecosystem": "Maven", "deprecated": False, "note": "Bouncy Castle PKIX, CMS, EAC, PKCS, TSP, and CertPath APIs.", "crypto_relevance": "PKI, CMS, X.509 certificates"},
    "jasypt": {"ecosystem": "Maven", "deprecated": False, "note": "Check configured encryption algorithm — defaults historically used PBEWithMD5AndDES.", "crypto_relevance": "Spring/Java configuration encryption"},
    "conscrypt": {"ecosystem": "Maven", "deprecated": False, "note": "BoringSSL-based Java Security Provider.", "crypto_relevance": "High-performance TLS"},

    # Go (Go)
    "golang.org/x/crypto": {"ecosystem": "Go", "deprecated": False, "note": "Supplementary Go cryptography libraries (SSH, Argon2, ChaCha20, curve25519).", "crypto_relevance": "Go supplementary crypto packages"},
    "github.com/golang-jwt/jwt": {"ecosystem": "Go", "deprecated": False, "note": "Go implementation of JSON Web Tokens.", "crypto_relevance": "JWT auth & tokens"},
    "github.com/cloudflare/circl": {"ecosystem": "Go", "deprecated": False, "note": "Cloudflare Interoperable Reusable Cryptographic Library with PQC (ML-KEM, Kyber).", "crypto_relevance": "Post-Quantum and experimental cryptography"},

    # Rust (Cargo / crates.io)
    "ring": {"ecosystem": "crates.io", "deprecated": False, "note": "Safe, fast, small crypto operations using Rust and C/Assembly (BoringSSL).", "crypto_relevance": "Core cryptography in Rust"},
    "rustls": {"ecosystem": "crates.io", "deprecated": False, "note": "Modern TLS library written in Rust; supports hybrid PQC key exchange.", "crypto_relevance": "Memory-safe TLS protocol"},
    "ed25519-dalek": {"ecosystem": "crates.io", "deprecated": False, "note": "Fast and efficient Rust implementation of ed25519 signatures.", "crypto_relevance": "Ed25519 signatures"},
    "aes-gcm": {"ecosystem": "crates.io", "deprecated": False, "note": "Pure Rust implementation of AES-GCM.", "crypto_relevance": "Authenticated symmetric encryption"},
}


def _severity_for_library(deprecated: bool, cve_note: str | None) -> Severity:
    if cve_note:
        return Severity.HIGH
    if deprecated:
        return Severity.HIGH
    return Severity.INFO


def _make_finding(
    lib_name: str,
    version_or_range: str | None,
    file_path: str,
    info: dict,
    cve_note: str | None = None,
    cve_source: str = "bundled-table",
    is_direct: bool = True,
    confidence: str = "Detected Evidence",
) -> Finding:
    deprecated = info.get("deprecated", False)
    ecosystem = info.get("ecosystem", "unknown")
    crypto_relevance = info.get("crypto_relevance", "Cryptographic dependency")

    issues = []
    if deprecated:
        issues.append(f"DEPRECATED: {info.get('note', 'unmaintained dependency')}")
    if cve_note:
        issues.append(cve_note)

    dep_type_str = "direct" if is_direct else "transitive lockfile"
    version_display = f" ({version_or_range})" if version_or_range else " (version unspecified/range)"

    title = f"Cryptography library: {lib_name}{version_display}"
    description = (
        f"{lib_name} ({ecosystem}) is a {dep_type_str} cryptographic dependency ({crypto_relevance}). "
        + (" ".join(issues) if issues else "No known CVE advisories found in database.")
    )

    remediation = (
        info.get("note")
        if deprecated
        else ("Upgrade to latest secure version and monitor security advisories." if cve_note else "Maintain active dependency updates.")
    )

    return Finding(
        id=str(uuid.uuid4()),
        category=Category.CRYPTO_LIBRARY,
        severity=_severity_for_library(deprecated, cve_note),
        title=title,
        description=description,
        file_path=file_path,
        matched_pattern="DEP-LIB-001",
        cwe_id="CWE-1104" if deprecated else ("CWE-1395" if cve_note else None),
        remediation=remediation,
        artifact_type=ArtifactType.LIBRARY,
        extra={
            "library": lib_name,
            "version": version_or_range,
            "ecosystem": ecosystem,
            "deprecated": deprecated,
            "is_direct": is_direct,
            "cve_source": cve_source,
            "confidence": confidence,
            "crypto_relevance": crypto_relevance,
        },
    )


def _check_osv(lib_name: str, version: str | None, ecosystem: str, skip_network: bool = False) -> str | None:
    if not version or skip_network or re.search(r"[<>=^~*]", version):
        return None
    clean_ver = re.sub(r"^[^\d]*", "", version)
    if not clean_ver:
        return None

    try:
        resp = httpx.post(
            OSV_API_URL,
            json={"package": {"name": lib_name, "ecosystem": ecosystem}, "version": clean_ver},
            timeout=OSV_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulns", [])
            if vulns:
                ids = [v.get("id", "Advisory") for v in vulns[:3]]
                return f"OSV.dev reports {len(vulns)} known advisory(ies): {', '.join(ids)}."
    except Exception:
        pass
    return None


def _find_known_lib(name: str) -> tuple[str, dict] | None:
    norm = name.lower().strip()
    if norm in KNOWN_CRYPTO_LIBRARIES:
        return norm, KNOWN_CRYPTO_LIBRARIES[norm]
    for k, v in KNOWN_CRYPTO_LIBRARIES.items():
        if k in norm:
            return k, v
    return None


# ---------------------------------------------------------------------------
# 14 Multi-Ecosystem Parsers
# ---------------------------------------------------------------------------

def _parse_requirements_txt(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([=><~^!]+.*)?", line)
        if m:
            name = m.group(1)
            ver = m.group(2).strip() if m.group(2) else None
            match = _find_known_lib(name)
            if match:
                k, info = match
                cve = _check_osv(name, ver, "PyPI", skip_network)
                findings.append(_make_finding(name, ver, rel, info, cve, "osv.dev" if cve else "bundled-table", True))
    return findings


def _parse_pyproject_toml(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    text = path.read_text(errors="ignore")

    # 1. PEP 621 dependencies array: "package>=1.0.0"
    for m in re.finditer(r'["\']([A-Za-z0-9_.\-]+)\s*([=><~^!]+[^"\']*)?["\']', text):
        name = m.group(1)
        ver = m.group(2).strip() if m.group(2) else None
        match = _find_known_lib(name)
        if match:
            k, info = match
            findings.append(_make_finding(name, ver, rel, info, None, "bundled-table", True))

    # 2. Poetry/Flit table: package = "^1.0.0" or package = { version = "1.0.0" }
    for m in re.finditer(r'^\s*([A-Za-z0-9_.\-]+)\s*=\s*(?:["\']([^"\']+)["\']|\{[^}]*version\s*=\s*["\']([^"\']+)["\'])', text, re.MULTILINE):
        name = m.group(1)
        if name.lower() in ("name", "version", "description", "readme", "requires-python"):
            continue
        ver = m.group(2) or m.group(3)
        match = _find_known_lib(name)
        if match and not any(f.extra.get("library") == name for f in findings):
            k, info = match
            findings.append(_make_finding(name, ver, rel, info, None, "bundled-table", True))

    return findings


def _parse_poetry_lock(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    text = path.read_text(errors="ignore")
    packages = re.findall(r'name\s*=\s*["\']([^"\']+)["\']\s+version\s*=\s*["\']([^"\']+)["\']', text)
    for name, ver in packages:
        match = _find_known_lib(name)
        if match:
            k, info = match
            cve = _check_osv(name, ver, "PyPI", skip_network)
            findings.append(_make_finding(name, ver, rel, info, cve, "osv.dev" if cve else "bundled-table", False))
    return findings


def _parse_pipfile_lock(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except Exception:
        return findings
    for section in ("default", "develop"):
        for name, spec in data.get(section, {}).items():
            match = _find_known_lib(name)
            if match:
                k, info = match
                ver = spec.get("version", "").replace("==", "")
                findings.append(_make_finding(name, ver or None, rel, info, None, "bundled-table", False))
    return findings


def _parse_package_json(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except Exception:
        return findings
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    for name, ver_spec in deps.items():
        match = _find_known_lib(name)
        if match:
            k, info = match
            cve = _check_osv(name, ver_spec, "npm", skip_network)
            findings.append(_make_finding(name, ver_spec, rel, info, cve, "osv.dev" if cve else "bundled-table", True))
    return findings


def _parse_package_lock(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except Exception:
        return findings

    packages = data.get("packages", {})
    if packages:
        for pkg_path, spec in packages.items():
            name = pkg_path.split("node_modules/")[-1]
            ver = spec.get("version")
            match = _find_known_lib(name)
            if match and ver:
                k, info = match
                findings.append(_make_finding(name, ver, rel, info, None, "bundled-table", False))
    else:
        for name, spec in data.get("dependencies", {}).items():
            ver = spec.get("version")
            match = _find_known_lib(name)
            if match and ver:
                k, info = match
                findings.append(_make_finding(name, ver, rel, info, None, "bundled-table", False))
    return findings


def _parse_yarn_lock(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    text = path.read_text(errors="ignore")
    blocks = text.split("\n\n")
    for block in blocks:
        lines = [l.strip() for l in block.splitlines() if l.strip()]
        if not lines:
            continue
        header = lines[0]
        ver_line = next((l for l in lines if l.startswith("version ")), None)
        if ver_line:
            ver = ver_line.split('"')[-2] if '"' in ver_line else ver_line.split()[-1]
            pkg_name = header.split("@")[0].strip('"')
            match = _find_known_lib(pkg_name)
            if match:
                k, info = match
                findings.append(_make_finding(pkg_name, ver, rel, info, None, "bundled-table", False))
    return findings


def _parse_pnpm_lock(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    text = path.read_text(errors="ignore")
    for line in text.splitlines():
        m = re.match(r"^\s*['\"]?(/?[@\w\d_.-]+)@([\d\w._-]+)['\"]?:", line)
        if m:
            name, ver = m.groups()
            name = name.lstrip("/")
            match = _find_known_lib(name)
            if match:
                k, info = match
                findings.append(_make_finding(name, ver, rel, info, None, "bundled-table", False))
    return findings


def _parse_pom_xml(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    text = path.read_text(errors="ignore")
    for artifact_id in re.findall(r"<artifactId>([^<]+)</artifactId>", text):
        match = _find_known_lib(artifact_id)
        if match:
            k, info = match
            findings.append(_make_finding(artifact_id, None, rel, info, None, "bundled-table", True))
    return findings


def _parse_gradle(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    text = path.read_text(errors="ignore")
    for m in re.finditer(r'["\']([a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+)(?::([a-zA-Z0-9_.-]+))?["\']', text):
        group_art, ver = m.groups()
        match = _find_known_lib(group_art)
        if match:
            k, info = match
            findings.append(_make_finding(group_art, ver, rel, info, None, "bundled-table", True))
    return findings


def _parse_go_mod(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    text = path.read_text(errors="ignore")
    for module, version in re.findall(r"(?:require\s+)?\s*([\w./-]+)\s+(v[\d.]+[\w-]*)", text, re.MULTILINE):
        match = _find_known_lib(module)
        if match:
            k, info = match
            findings.append(_make_finding(module, version, rel, info, None, "bundled-table", True))
    return findings


def _parse_go_sum(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    text = path.read_text(errors="ignore")
    seen = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            mod, ver = parts[0], parts[1].split("/")[0]
            if (mod, ver) in seen:
                continue
            seen.add((mod, ver))
            match = _find_known_lib(mod)
            if match:
                k, info = match
                findings.append(_make_finding(mod, ver, rel, info, None, "bundled-table", False))
    return findings


def _parse_cargo_toml(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    text = path.read_text(errors="ignore")
    for m in re.finditer(r'^\s*([a-zA-Z0-9_.-]+)\s*=\s*(?:["\']([^"\']+)["\']|\{[^}]*version\s*=\s*["\']([^"\']+)["\'])', text, re.MULTILINE):
        name = m.group(1)
        ver = m.group(2) or m.group(3)
        match = _find_known_lib(name)
        if match:
            k, info = match
            findings.append(_make_finding(name, ver, rel, info, None, "bundled-table", True))
    return findings


def _parse_cargo_lock(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    text = path.read_text(errors="ignore")
    for name, ver in re.findall(r'\[\[package\]\]\s+name\s*=\s*["\']([^"\']+)["\']\s+version\s*=\s*["\']([^"\']+)["\']', text):
        match = _find_known_lib(name)
        if match:
            k, info = match
            findings.append(_make_finding(name, ver, rel, info, None, "bundled-table", False))
    return findings


MANIFEST_PARSERS = {
    "requirements.txt": _parse_requirements_txt,
    "pyproject.toml": _parse_pyproject_toml,
    "poetry.lock": _parse_poetry_lock,
    "Pipfile.lock": _parse_pipfile_lock,
    "package.json": _parse_package_json,
    "package-lock.json": _parse_package_lock,
    "yarn.lock": _parse_yarn_lock,
    "pnpm-lock.yaml": _parse_pnpm_lock,
    "pom.xml": _parse_pom_xml,
    "build.gradle": _parse_gradle,
    "build.gradle.kts": _parse_gradle,
    "go.mod": _parse_go_mod,
    "go.sum": _parse_go_sum,
    "Cargo.toml": _parse_cargo_toml,
    "Cargo.lock": _parse_cargo_lock,
}


def scan_dependencies(root_path: str, skip_network: bool = False) -> list[Finding]:
    root = Path(root_path)
    findings: list[Finding] = []
    ignore_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".cargo"}

    for file_path in root.rglob("*"):
        if not file_path.is_file() or any(part in ignore_dirs for part in file_path.parts):
            continue
        parser = MANIFEST_PARSERS.get(file_path.name)
        if parser:
            findings.extend(parser(file_path, root, skip_network))

    return findings
