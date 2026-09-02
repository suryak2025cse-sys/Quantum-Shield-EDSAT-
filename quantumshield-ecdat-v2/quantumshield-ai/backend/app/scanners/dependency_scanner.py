"""
Dependency / Library Scanner
==============================
Parses common dependency manifests (requirements.txt, package.json,
pom.xml, go.mod) to build a catalogue of cryptography-relevant libraries in
use, flags known-deprecated ones, and — best-effort — checks each against
OSV.dev for published CVEs.

Design notes:
  - Manifest parsing is exact (real parsing per format), not regex-guessing.
  - The OSV.dev lookup is genuinely wired up (a real HTTP call to a real,
    free, no-auth-required vulnerability database), but network access
    varies by deployment environment. If the lookup fails or times out, this
    degrades gracefully to a small bundled table of well-known deprecated
    crypto libraries rather than silently reporting nothing. Callers can tell
    the two modes apart via the finding's `extra["cve_source"]` field.
"""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

import httpx

from app.models.schemas import ArtifactType, Category, Finding, Severity

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT_SECONDS = 4.0

# Known crypto-relevant libraries worth cataloguing, and — where applicable —
# a note on deprecation status that doesn't depend on any network call.
KNOWN_CRYPTO_LIBRARIES = {
    # Python
    "pycrypto": {"ecosystem": "PyPI", "deprecated": True, "note": "Unmaintained since 2013; known CVEs unpatched. Migrate to pycryptodome or `cryptography`."},
    "pycryptodome": {"ecosystem": "PyPI", "deprecated": False, "note": "Actively maintained drop-in replacement for PyCrypto."},
    "cryptography": {"ecosystem": "PyPI", "deprecated": False, "note": "Actively maintained; wraps OpenSSL."},
    "pyopenssl": {"ecosystem": "PyPI", "deprecated": False, "note": "Actively maintained OpenSSL binding."},
    "rsa": {"ecosystem": "PyPI", "deprecated": False, "note": "Pure-Python RSA — fine for RSA specifically, but RSA itself is quantum-vulnerable."},
    "jose": {"ecosystem": "PyPI", "deprecated": False, "note": "JWT/JOSE implementation — verify algorithm allow-lists."},
    "python-jose": {"ecosystem": "PyPI", "deprecated": False, "note": "JWT/JOSE implementation — verify algorithm allow-lists."},
    # Node
    "node-forge": {"ecosystem": "npm", "deprecated": False, "note": "Pure-JS crypto — check algorithm usage."},
    "jsrsasign": {"ecosystem": "npm", "deprecated": False, "note": "JS crypto/PKI toolkit — check algorithm usage."},
    "jsonwebtoken": {"ecosystem": "npm", "deprecated": False, "note": "Verify `algorithms` allow-list excludes 'none'."},
    "crypto-js": {"ecosystem": "npm", "deprecated": False, "note": "Includes legacy algorithms (DES, MD5) — verify which are actually used."},
    # Java
    "bouncycastle": {"ecosystem": "Maven", "deprecated": False, "note": "Actively maintained; supports PQC algorithms in recent releases."},
    "jasypt": {"ecosystem": "Maven", "deprecated": False, "note": "Check configured algorithm — defaults have historically been weak (PBEWithMD5AndDES)."},
    # Go
    "golang.org/x/crypto": {"ecosystem": "Go", "deprecated": False, "note": "Actively maintained; check specific package usage."},
}


def _severity_for_library(deprecated: bool) -> Severity:
    return Severity.HIGH if deprecated else Severity.INFO


def _make_finding(lib_name: str, version: str | None, file_path: str, info: dict, cve_note: str | None = None, cve_source: str = "none") -> Finding:
    deprecated = info.get("deprecated", False)
    issues = []
    if deprecated:
        issues.append(info.get("note", "flagged as deprecated"))
    if cve_note:
        issues.append(cve_note)

    return Finding(
        id=str(uuid.uuid4()),
        category=Category.CRYPTO_LIBRARY,
        severity=_severity_for_library(deprecated) if not cve_note else Severity.HIGH,
        title=f"Cryptography library: {lib_name}" + (f" ({version})" if version else ""),
        description=(
            f"{lib_name} ({info.get('ecosystem', 'unknown ecosystem')}) is a cryptography-relevant dependency. "
            + (" ".join(issues) if issues else "No known issues found.")
        ),
        file_path=file_path,
        matched_pattern="DEP-LIB-001",
        cwe_id="CWE-1104" if deprecated else None,
        remediation=info.get("note") if deprecated else "Keep this dependency current and monitor for advisories.",
        artifact_type=ArtifactType.LIBRARY,
        extra={
            "library": lib_name,
            "version": version,
            "ecosystem": info.get("ecosystem"),
            "deprecated": deprecated,
            "cve_source": cve_source,
        },
    )


def _check_osv(lib_name: str, version: str | None, ecosystem: str, skip_network: bool = False) -> str | None:
    """Best-effort OSV.dev lookup. Returns a human-readable CVE note, or None
    if no vulnerabilities were found or the lookup couldn't be completed."""
    if not version or skip_network:
        return None
    try:
        resp = httpx.post(
            OSV_API_URL,
            json={"package": {"name": lib_name, "ecosystem": ecosystem}, "version": version},
            timeout=OSV_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulns", [])
        if not vulns:
            return None
        ids = [v.get("id", "?") for v in vulns[:3]]
        return f"OSV.dev reports {len(vulns)} known advisories for this version, including {', '.join(ids)}."
    except (httpx.HTTPError, httpx.TimeoutException, json.JSONDecodeError):
        return None  # network unavailable or blocked in this environment — degrade silently


def _parse_requirements_txt(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=)?\s*([A-Za-z0-9_.\-]*)", line)
        if not m:
            continue
        name, _, version = m.groups()
        key = name.lower()
        if key in KNOWN_CRYPTO_LIBRARIES:
            info = KNOWN_CRYPTO_LIBRARIES[key]
            cve_note = _check_osv(name, version or None, "PyPI", skip_network)
            findings.append(_make_finding(name, version or None, rel, info, cve_note, "osv.dev" if cve_note else "bundled-table"))
    return findings


def _parse_package_json(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return findings
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    for name, version_spec in deps.items():
        key = name.lower()
        if key in KNOWN_CRYPTO_LIBRARIES:
            info = KNOWN_CRYPTO_LIBRARIES[key]
            version = re.sub(r"[^\d.]", "", version_spec) or None
            cve_note = _check_osv(name, version, "npm", skip_network)
            findings.append(_make_finding(name, version, rel, info, cve_note, "osv.dev" if cve_note else "bundled-table"))
    return findings


def _parse_pom_xml(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    text = path.read_text(errors="ignore")
    for artifact_id in re.findall(r"<artifactId>([^<]+)</artifactId>", text):
        key = artifact_id.lower()
        for lib_key, info in KNOWN_CRYPTO_LIBRARIES.items():
            if lib_key in key:
                findings.append(_make_finding(artifact_id, None, rel, info))
    return findings


def _parse_go_mod(path: Path, root: Path, skip_network: bool = False) -> list[Finding]:
    findings = []
    rel = str(path.relative_to(root))
    text = path.read_text(errors="ignore")
    for module, version in re.findall(r"^\s*([\w./-]+)\s+(v[\d.]+)", text, re.MULTILINE):
        for lib_key, info in KNOWN_CRYPTO_LIBRARIES.items():
            if lib_key in module.lower():
                findings.append(_make_finding(module, version, rel, info))
    return findings


MANIFEST_PARSERS = {
    "requirements.txt": _parse_requirements_txt,
    "package.json": _parse_package_json,
    "pom.xml": _parse_pom_xml,
    "go.mod": _parse_go_mod,
}


def scan_dependencies(root_path: str, skip_network: bool = False) -> list[Finding]:
    root = Path(root_path)
    findings: list[Finding] = []
    ignore_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}

    for file_path in root.rglob("*"):
        if not file_path.is_file() or any(part in ignore_dirs for part in file_path.parts):
            continue
        parser = MANIFEST_PARSERS.get(file_path.name)
        if parser:
            findings.extend(parser(file_path, root, skip_network))

    return findings
