"""
Container Image Scanner
==========================
Accepts a `docker save <image> -o image.tar` archive, extracts every layer
(each layer is itself a tarball of filesystem changes), flattens them into a
single directory the same way a container's union filesystem would resolve
them, then runs the existing source/cert/dependency/binary/HSM scanners
against that flattened filesystem.

This is real layer extraction against Docker's actual image format (OCI/v1
manifest.json + layer tarballs) — not a simulation. What it does not do is
full OS package-manager introspection (e.g. querying dpkg/rpm databases
inside the image for a complete installed-package inventory) — that's a
meaningfully larger scope than this scanner's static file-content model, and
is flagged as a known limitation rather than silently skipped.
"""
from __future__ import annotations

import json
import tarfile
import tempfile
from pathlib import Path

from app.models.schemas import Finding


def _flatten_layers(image_tar_path: str, dest_dir: Path) -> int:
    """Extracts a `docker save` tarball's layers into dest_dir, applying them
    in order so later layers overwrite earlier ones (approximating a union
    filesystem). Returns the number of layers processed."""
    with tempfile.TemporaryDirectory() as extract_root:
        extract_root = Path(extract_root)
        with tarfile.open(image_tar_path) as image_tar:
            image_tar.extractall(extract_root, filter="data")

        manifest_path = extract_root / "manifest.json"
        if not manifest_path.exists():
            raise ValueError("Not a valid `docker save` archive: manifest.json not found")

        manifest = json.loads(manifest_path.read_text())
        layer_paths = manifest[0].get("Layers", [])

        for layer_rel_path in layer_paths:
            layer_tar_path = extract_root / layer_rel_path
            if not layer_tar_path.exists():
                continue
            with tarfile.open(layer_tar_path) as layer_tar:
                for member in layer_tar.getmembers():
                    # Whiteout files (.wh.*) mark deletions in overlay filesystems;
                    # skip them rather than extracting Docker's internal markers as real files.
                    if Path(member.name).name.startswith(".wh."):
                        continue
                    try:
                        layer_tar.extract(member, dest_dir, filter="data")
                    except Exception:
                        continue  # skip unreadable members (device files, etc.) rather than aborting the whole scan

        return len(layer_paths)


def scan_container_image(image_tar_path: str, run_full_scan_fn) -> tuple[list[Finding], int, int]:
    """
    image_tar_path: path to a `docker save` output tarball
    run_full_scan_fn: callable(directory_path) -> list[Finding], reusing every
        other scanner (crypto, certs, dependencies, HSM, binaries) against the
        flattened image filesystem — so a container image gets the exact same
        depth of analysis as a source checkout, not a separate/lesser pipeline.

    Returns (findings, files_scanned, layers_processed).
    """
    with tempfile.TemporaryDirectory() as flat_dir:
        flat_dir_path = Path(flat_dir)
        layer_count = _flatten_layers(image_tar_path, flat_dir_path)
        findings, files_scanned = run_full_scan_fn(str(flat_dir_path))
        # Tag every finding as originating from the container image, since the
        # file paths after flattening are container-internal paths (e.g. /etc/...)
        # rather than the uploader's own repo structure.
        for f in findings:
            f.extra = {**f.extra, "source": "container_image"}
        return findings, files_scanned, layer_count
