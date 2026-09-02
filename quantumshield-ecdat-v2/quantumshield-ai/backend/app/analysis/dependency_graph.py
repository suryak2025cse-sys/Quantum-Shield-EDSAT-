"""
Crypto Dependency Graph Builder
================================
Builds a graph of relationships between cryptographic assets, keys,
certificates, libraries, services, and files from a flat list of Findings.

All edges are HEURISTICALLY derived from static analysis:
  - Shared file path → algorithm node is "contained in" a file node
  - Certificate findings → cert node "uses" the algorithm it was signed with
  - Library/dependency findings → library node "used by" application node
  - HSM/KMS findings → service node "depends on" algorithm node

Because we don't have runtime call graphs (that would require executing the
application), every edge carries `heuristic=True` and the graph object itself
has a disclaimer note. Callers must never present these as observed runtime
relationships.

Node ID conventions:
  - algorithm: "algo::<rule_id>::<file_path>"
  - file:      "file::<normalized_path>"
  - cert:      "cert::<finding_id>"
  - library:   "lib::<title>"
  - service:   "svc::<file_path>"
  - app:       "app::root"
"""
from __future__ import annotations

import hashlib
from collections import defaultdict

from app.models.schemas import (
    ArtifactType,
    Category,
    CryptoDependencyGraph,
    DependencyEdge,
    DependencyNode,
    Finding,
    NodeType,
)


def _safe_id(parts: list[str]) -> str:
    return hashlib.sha256("::".join(parts).encode()).hexdigest()[:16]


def build_crypto_dependency_graph(findings: list[Finding]) -> CryptoDependencyGraph:
    """
    Convert a flat list of Findings into a directed dependency graph.

    Node types created:
      FILE        — every unique file_path that contains a finding
      ALGORITHM   — each unique crypto rule fired (grouped by rule + file)
      CERTIFICATE — each certificate finding
      LIBRARY     — each crypto-library / dependency finding
      SERVICE     — each HSM/cloud-KMS finding
      APPLICATION — one root "application" node per scan

    Edge types created (all heuristic=True):
      algorithm  → contained-in → file
      cert       → uses         → algorithm (if algorithm exists in same file)
      cert       → contained-in → file
      library    → depends-on   → application
      service    → uses         → algorithm (if algorithm in same file/dir)
      file       → contained-in → application
    """
    nodes: dict[str, DependencyNode] = {}
    edges: list[DependencyEdge] = []

    # --- Root application node ---
    app_id = "app::root"
    nodes[app_id] = DependencyNode(
        id=app_id,
        node_type=NodeType.APPLICATION,
        label="Application Root",
    )

    # --- Index findings by file and category ---
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_file[f.file_path].append(f)

    def add_edge(src: str, tgt: str, rel: str) -> None:
        # Dedup edges
        key = f"{src}->{tgt}:{rel}"
        if not any(e.source == src and e.target == tgt and e.relationship == rel for e in edges):
            edges.append(DependencyEdge(source=src, target=tgt, relationship=rel, heuristic=True))

    # --- File nodes ---
    for file_path, file_findings in by_file.items():
        file_id = f"file::{_safe_id([file_path])}"
        if file_id not in nodes:
            nodes[file_id] = DependencyNode(
                id=file_id,
                node_type=NodeType.FILE,
                label=file_path,
                metadata={"path": file_path, "finding_count": len(file_findings)},
            )
        add_edge(file_id, app_id, "contained-in")

        for f in file_findings:
            _handle_finding(f, file_id, file_path, nodes, edges, add_edge)

    return CryptoDependencyGraph(nodes=list(nodes.values()), edges=edges)


def _handle_finding(
    f: Finding,
    file_id: str,
    file_path: str,
    nodes: dict[str, DependencyNode],
    edges: list[DependencyEdge],
    add_edge,
) -> None:
    """Dispatch a finding to the appropriate node-creation logic."""
    if f.artifact_type == ArtifactType.CERTIFICATE or f.category == Category.CERTIFICATE_ISSUE:
        cert_id = f"cert::{f.id}"
        if cert_id not in nodes:
            nodes[cert_id] = DependencyNode(
                id=cert_id,
                node_type=NodeType.CERTIFICATE,
                label=f.title,
                severity=f.severity.value,
                criticality=f.criticality.value if f.criticality else None,
                mosca_risk=f.mosca.risk_level.value if f.mosca else None,
                finding_ids=[f.id],
                metadata={
                    "file": file_path,
                    "subject": f.extra.get("subject"),
                    "issuer": f.extra.get("issuer"),
                    "not_after": f.extra.get("not_valid_after"),
                },
            )
        add_edge(cert_id, file_id, "contained-in")
        # Cert uses whatever algorithm is in the same file
        algo_id = f"algo::cert::{_safe_id([file_path])}"
        _ensure_algo_node(algo_id, f"Certificate signing algo ({file_path})", f, nodes)
        add_edge(cert_id, algo_id, "uses")
        add_edge(algo_id, file_id, "contained-in")

    elif f.category == Category.CRYPTO_LIBRARY or f.category == Category.DEPENDENCY_CVE:
        lib_id = f"lib::{_safe_id([f.title])}"
        if lib_id not in nodes:
            nodes[lib_id] = DependencyNode(
                id=lib_id,
                node_type=NodeType.LIBRARY,
                label=f.title,
                severity=f.severity.value,
                finding_ids=[f.id],
                metadata={"file": file_path},
            )
        elif f.id not in nodes[lib_id].finding_ids:
            nodes[lib_id].finding_ids.append(f.id)
        add_edge(lib_id, file_id, "contained-in")
        add_edge(lib_id, "app::root", "used-by")

    elif f.category == Category.HSM_CLOUD_KMS:
        svc_id = f"svc::{_safe_id([file_path])}"
        if svc_id not in nodes:
            nodes[svc_id] = DependencyNode(
                id=svc_id,
                node_type=NodeType.SERVICE,
                label=f"KMS/HSM service ({file_path})",
                severity=f.severity.value,
                finding_ids=[f.id],
                metadata={"file": file_path},
            )
        add_edge(svc_id, file_id, "contained-in")

    elif f.category in (
        Category.QUANTUM_VULNERABLE_CRYPTO,
        Category.CLASSICAL_CRYPTO_WEAKNESS,
        Category.AUTH_WEAKNESS,
    ):
        algo_id = f"algo::{f.matched_pattern}::{_safe_id([file_path])}"
        _ensure_algo_node(algo_id, f.title, f, nodes)
        add_edge(algo_id, file_id, "contained-in")

    elif f.artifact_type == ArtifactType.RELATED_MATERIAL or f.category == Category.SECRET:
        key_id = f"key::{f.id}"
        nodes[key_id] = DependencyNode(
            id=key_id,
            node_type=NodeType.KEY,
            label=f.title,
            severity=f.severity.value,
            criticality=f.criticality.value if f.criticality else None,
            finding_ids=[f.id],
            metadata={"file": file_path},
        )
        add_edge(key_id, file_id, "contained-in")


def _ensure_algo_node(
    algo_id: str,
    label: str,
    f: Finding,
    nodes: dict[str, DependencyNode],
) -> None:
    if algo_id not in nodes:
        nodes[algo_id] = DependencyNode(
            id=algo_id,
            node_type=NodeType.ALGORITHM,
            label=label,
            severity=f.severity.value,
            criticality=f.criticality.value if f.criticality else None,
            mosca_risk=f.mosca.risk_level.value if f.mosca else None,
            finding_ids=[f.id],
        )
    elif f.id not in nodes[algo_id].finding_ids:
        nodes[algo_id].finding_ids.append(f.id)
