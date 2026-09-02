"""
Exposure Classification (internal vs. external facing)
=========================================================
Static source analysis cannot definitively know an application's real
network topology — that lives in infrastructure, not code. What it *can* do
is read the infrastructure-as-code artifacts that are usually committed
alongside the application: Dockerfiles and Kubernetes manifests. This module
looks for concrete signals in those files:

  - Dockerfile `EXPOSE` directive on a non-loopback port -> likely reachable
  - Kubernetes Service of type LoadBalancer or NodePort -> externally reachable
  - Kubernetes Ingress resource present -> externally reachable
  - Kubernetes Service of type ClusterIP only, no Ingress -> internal-only

If none of these are found anywhere in the scanned project, exposure is
reported as UNKNOWN rather than guessed — an incorrect internal/external
label is worse than an honest "we don't know," since it could misdirect
remediation priority.
"""
from __future__ import annotations

import re
from pathlib import Path

from app.models.schemas import Exposure

EXPOSE_RE = re.compile(r"^\s*EXPOSE\s+(\d+)", re.IGNORECASE | re.MULTILINE)
K8S_SERVICE_TYPE_RE = re.compile(r"^\s*type:\s*(LoadBalancer|NodePort|ClusterIP)\s*$", re.IGNORECASE | re.MULTILINE)
K8S_KIND_INGRESS_RE = re.compile(r"^\s*kind:\s*Ingress\s*$", re.IGNORECASE | re.MULTILINE)
K8S_KIND_SERVICE_RE = re.compile(r"^\s*kind:\s*Service\s*$", re.IGNORECASE | re.MULTILINE)

IGNORE_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}


def scan_exposure_signals(root_path: str) -> Exposure:
    """Scans the project root once for infra manifests and returns a single
    project-level exposure verdict (used to annotate all findings in that scan,
    since a whole deployable unit typically shares one exposure profile)."""
    root = Path(root_path)
    found_external = False
    found_internal_only = False

    for file_path in root.rglob("*"):
        if not file_path.is_file() or any(part in IGNORE_DIRS for part in file_path.parts):
            continue

        name = file_path.name.lower()
        if name == "dockerfile" or name.startswith("dockerfile."):
            try:
                text = file_path.read_text(errors="ignore")
            except OSError:
                continue
            for port in EXPOSE_RE.findall(text):
                if port not in ("127", "0"):  # ignore obviously-loopback-only declarations
                    found_external = True

        elif file_path.suffix.lower() in (".yaml", ".yml"):
            try:
                text = file_path.read_text(errors="ignore")
            except OSError:
                continue
            if K8S_KIND_INGRESS_RE.search(text):
                found_external = True
            if K8S_KIND_SERVICE_RE.search(text):
                m = K8S_SERVICE_TYPE_RE.search(text)
                if m:
                    svc_type = m.group(1).lower()
                    if svc_type in ("loadbalancer", "nodeport"):
                        found_external = True
                    elif svc_type == "clusterip":
                        found_internal_only = True

    if found_external:
        return Exposure.EXTERNAL
    if found_internal_only:
        return Exposure.INTERNAL
    return Exposure.UNKNOWN
