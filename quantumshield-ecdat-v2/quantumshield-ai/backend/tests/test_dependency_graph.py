"""
Test suite for Crypto Dependency Graph Builder
"""
from app.analysis.dependency_graph import build_crypto_dependency_graph
from app.models.schemas import (
    ArtifactType,
    Category,
    Criticality,
    Finding,
    NodeType,
    Severity,
)


def _make_finding(id_str, category, artifact_type, file_path, pattern="QC-RSA-001"):
    return Finding(
        id=id_str,
        severity=Severity.HIGH,
        criticality=Criticality.HIGH,
        category=category,
        artifact_type=artifact_type,
        title=f"Test Finding {id_str}",
        description="Test description",
        file_path=file_path,
        matched_pattern=pattern,
    )


def test_dependency_graph_empty():
    graph = build_crypto_dependency_graph([])
    assert len(graph.nodes) == 1  # Root application node
    assert graph.nodes[0].node_type == NodeType.APPLICATION
    assert len(graph.edges) == 0


def test_dependency_graph_basic():
    f1 = _make_finding("f1", Category.QUANTUM_VULNERABLE_CRYPTO, ArtifactType.ALGORITHM, "src/auth.py")
    f2 = _make_finding("f2", Category.CERTIFICATE_ISSUE, ArtifactType.CERTIFICATE, "certs/server.crt")

    graph = build_crypto_dependency_graph([f1, f2])
    node_types = {n.node_type for n in graph.nodes}

    assert NodeType.APPLICATION in node_types
    assert NodeType.FILE in node_types
    assert NodeType.ALGORITHM in node_types
    assert NodeType.CERTIFICATE in node_types

    # Every edge must carry heuristic=True
    for edge in graph.edges:
        assert edge.heuristic is True
