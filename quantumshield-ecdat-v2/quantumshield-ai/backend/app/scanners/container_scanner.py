"""
Container Image Scanner
=========================
Processes OCI / Docker `docker save` tar archives.

Features:
  - Multi-layer ordered extraction simulating union filesystem
  - Handles whiteout deletion markers (.wh.<filename>) and opaque directories (.wh..wh..opq)
  - Inspects OS package databases:
      * Debian / Ubuntu: /var/lib/dpkg/status
      * Alpine: /lib/apk/db/installed
  - Scans extracted image rootfs across all standard scanners (crypto, certs, deps, binaries, HSM)
  - Does NOT execute container or customer code
"""
from __future__ import annotations

import json
import re
import shutil
import tarfile
import tempfile
import uuid
from pathlib import Path
from typing import Callable

from app.models.schemas import ArtifactType, Category, Finding, Severity

OS_CRYPTO_PACKAGES = {
    "openssl": {"desc": "Core SSL/TLS cryptographic engine", "severity": Severity.INFO},
    "libssl": {"desc": "OpenSSL runtime library", "severity": Severity.INFO},
    "libssl1.1": {"desc": "Deprecated OpenSSL 1.1 runtime library", "severity": Severity.MEDIUM},
    "libssl1.0": {"desc": "End-of-life OpenSSL 1.0 runtime library with critical CVEs", "severity": Severity.HIGH},
    "gnutls": {"desc": "GNU TLS secure communications library", "severity": Severity.INFO},
    "libgcrypt": {"desc": "General purpose cryptographic library", "severity": Severity.INFO},
    "ca-certificates": {"desc": "System root CA trust store", "severity": Severity.INFO},
    "libnettle": {"desc": "Low-level cryptographic library", "severity": Severity.INFO},
}


def _scan_os_packages(rootfs: Path) -> list[Finding]:
    """Inspects dpkg and apk package databases inside container filesystem."""
    findings: list[Finding] = []

    # 1. Debian / Ubuntu dpkg
    dpkg_status = rootfs / "var" / "lib" / "dpkg" / "status"
    sorted_pkgs = sorted(OS_CRYPTO_PACKAGES.items(), key=lambda x: len(x[0]), reverse=True)
    if dpkg_status.exists():
        text = dpkg_status.read_text(errors="ignore")
        for block in text.split("\n\n"):
            pkg_m = re.search(r"^Package:\s*([^\s]+)", block, re.MULTILINE)
            ver_m = re.search(r"^Version:\s*([^\s]+)", block, re.MULTILINE)
            if pkg_m and ver_m:
                pkg = pkg_m.group(1).lower()
                ver = ver_m.group(1)
                for known_pkg, info in sorted_pkgs:
                    if known_pkg in pkg:
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                category=Category.CRYPTO_LIBRARY,
                                severity=info["severity"],
                                title=f"Container OS Package: {pkg} ({ver})",
                                description=f"Installed Debian/Ubuntu package in container image: {info['desc']}.",
                                file_path="var/lib/dpkg/status",
                                matched_pattern="CONT-OS-PKG-001",
                                artifact_type=ArtifactType.LIBRARY,
                                extra={
                                    "package": pkg,
                                    "version": ver,
                                    "ecosystem": "dpkg/debian",
                                    "source": "container_os_package",
                                },
                            )
                        )
                        break

    # 2. Alpine apk
    apk_installed = rootfs / "lib" / "apk" / "db" / "installed"
    if apk_installed.exists():
        text = apk_installed.read_text(errors="ignore")
        for block in text.split("\n\n"):
            pkg_m = re.search(r"^P:([^\n]+)", block, re.MULTILINE)
            ver_m = re.search(r"^V:([^\n]+)", block, re.MULTILINE)
            if pkg_m and ver_m:
                pkg = pkg_m.group(1).strip().lower()
                ver = ver_m.group(1).strip()
                for known_pkg, info in OS_CRYPTO_PACKAGES.items():
                    if known_pkg in pkg:
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                category=Category.CRYPTO_LIBRARY,
                                severity=info["severity"],
                                title=f"Container OS Package: {pkg} ({ver})",
                                description=f"Installed Alpine package in container image: {info['desc']}.",
                                file_path="lib/apk/db/installed",
                                matched_pattern="CONT-OS-PKG-002",
                                artifact_type=ArtifactType.LIBRARY,
                                extra={
                                    "package": pkg,
                                    "version": ver,
                                    "ecosystem": "apk/alpine",
                                    "source": "container_os_package",
                                },
                            )
                        )

    return findings


def _flatten_layers(image_tar_path: str, dest_dir: Path) -> int:
    """Extracts a `docker save` tarball's layers into dest_dir applying whiteouts."""
    with tempfile.TemporaryDirectory() as extract_root:
        extract_root_path = Path(extract_root)
        with tarfile.open(image_tar_path) as image_tar:
            image_tar.extractall(extract_root_path, filter="data")

        manifest_path = extract_root_path / "manifest.json"
        if not manifest_path.exists():
            raise ValueError("Not a valid `docker save` archive: manifest.json not found")

        manifest = json.loads(manifest_path.read_text(errors="ignore"))
        layer_paths = manifest[0].get("Layers", [])

        for layer_rel_path in layer_paths:
            layer_tar_path = extract_root_path / layer_rel_path
            if not layer_tar_path.exists():
                continue

            with tarfile.open(layer_tar_path) as layer_tar:
                for member in layer_tar.getmembers():
                    member_name = member.name
                    path_obj = Path(member_name)

                    # Opaque directory whiteout (.wh..wh..opq)
                    if path_obj.name == ".wh..wh..opq":
                        parent_dest = dest_dir / path_obj.parent
                        if parent_dest.exists() and parent_dest.is_dir():
                            shutil.rmtree(parent_dest, ignore_errors=True)
                            parent_dest.mkdir(parents=True, exist_ok=True)
                        continue

                    # File whiteout (.wh.<filename>)
                    if path_obj.name.startswith(".wh."):
                        target_file = path_obj.name[4:]
                        target_dest = dest_dir / path_obj.parent / target_file
                        if target_dest.exists():
                            if target_dest.is_dir():
                                shutil.rmtree(target_dest, ignore_errors=True)
                            else:
                                target_dest.unlink(missing_ok=True)
                        continue

                    try:
                        layer_tar.extract(member, dest_dir, filter="data")
                    except Exception:
                        continue

        return len(layer_paths)


def scan_container_image(image_tar_path: str, run_full_scan_fn: Callable) -> tuple[list[Finding], int, int]:
    """
    Extracts and scans Docker container tar archive.
    Returns (findings, files_scanned, layers_processed).
    """
    with tempfile.TemporaryDirectory() as flat_dir:
        flat_dir_path = Path(flat_dir)
        layer_count = _flatten_layers(image_tar_path, flat_dir_path)

        # 1. Run standard multi-scanner across rootfs
        findings, files_scanned = run_full_scan_fn(str(flat_dir_path))

        # 2. Inspect OS package managers
        os_findings = _scan_os_packages(flat_dir_path)
        findings.extend(os_findings)

        # Tag findings with container metadata
        for f in findings:
            f.extra = {**f.extra, "source": "container_image", "layer_count": layer_count}

        return findings, files_scanned, layer_count
