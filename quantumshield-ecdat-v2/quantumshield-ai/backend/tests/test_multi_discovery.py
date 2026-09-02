"""
Test Suite: Multi-Ecosystem Dependency Parsers, Deep X.509, Binary & Container Scanning
"""
from pathlib import Path
from app.scanners.dependency_scanner import scan_dependencies
from app.scanners.binary_scanner import _detect_format_and_arch, scan_binaries
from app.scanners.container_scanner import _scan_os_packages


def test_python_multi_manifests(tmp_path):
    (tmp_path / "requirements.txt").write_text("pycrypto==2.6.1\ncryptography>=42.0.0\n")
    (tmp_path / "pyproject.toml").write_text('[project.dependencies]\npycryptodome = ">=3.19.0"\n')
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "ecdsa"\nversion = "0.18.0"\n')

    findings = scan_dependencies(str(tmp_path), skip_network=True)
    libs = {f.extra.get("library") for f in findings}
    assert "pycrypto" in libs
    assert "cryptography" in libs
    assert "pycryptodome" in libs
    assert "ecdsa" in libs


def test_node_multi_manifests(tmp_path):
    pkg_json = '{"dependencies": {"jsonwebtoken": "^9.0.2", "node-forge": "1.3.1"}}'
    (tmp_path / "package.json").write_text(pkg_json)

    findings = scan_dependencies(str(tmp_path), skip_network=True)
    libs = {f.extra.get("library") for f in findings}
    assert "jsonwebtoken" in libs
    assert "node-forge" in libs


def test_jvm_and_go_and_rust_manifests(tmp_path):
    (tmp_path / "pom.xml").write_text("<project><dependencies><dependency><artifactId>bouncycastle</artifactId></dependency></dependencies></project>")
    (tmp_path / "go.mod").write_text("module example.com/app\n\nrequire golang.org/x/crypto v0.21.0\n")
    (tmp_path / "Cargo.toml").write_text('[dependencies]\nring = "0.17.8"\nrustls = "0.23.0"\n')

    findings = scan_dependencies(str(tmp_path), skip_network=True)
    libs = {f.extra.get("library") for f in findings}
    assert "bouncycastle" in libs
    assert "golang.org/x/crypto" in libs
    assert "ring" in libs
    assert "rustls" in libs


def test_binary_header_detection():
    elf_header = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3E\x00"  # ELF 64-bit x86_64
    fmt, arch = _detect_format_and_arch(elf_header)
    assert "ELF" in fmt
    assert arch == "x86_64"

    pe_header = b"MZ" + b"\x00" * 20
    fmt_pe, _ = _detect_format_and_arch(pe_header)
    assert "PE" in fmt_pe


def test_container_os_package_detection(tmp_path):
    dpkg_dir = tmp_path / "var" / "lib" / "dpkg"
    dpkg_dir.mkdir(parents=True)
    (dpkg_dir / "status").write_text("Package: libssl1.1\nVersion: 1.1.1f-1ubuntu2\nStatus: install ok installed\n\n")

    findings = _scan_os_packages(tmp_path)
    assert len(findings) == 1
    assert "libssl1.1" in findings[0].title
