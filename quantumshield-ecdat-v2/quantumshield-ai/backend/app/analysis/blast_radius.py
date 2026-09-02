"""
Migration Blast Radius Calculator
====================================
Given a CryptoDependencyGraph and the list of Findings, computes the
migration "blast radius" for each finding:

  - Direct dependencies: nodes that the affected node immediately connects to
  - Indirect dependencies: all transitively reachable nodes (BFS)
  - Rating: Low (0-2 total), Medium (3-7), High (8+)

All relationships come from the heuristic dependency graph — callers should
present blast radius as an estimate, not a measured runtime impact.
"""
from __future__ import annotations

from collections import deque, defaultdict

from app.models.schemas import (
    BlastRadius,
    BlastRating,
    CryptoDependencyGraph,
    Finding,
)

_RATING_THRESHOLDS = [
    (2, BlastRating.LOW),
    (7, BlastRating.MEDIUM),
]


def _rate(total: int) -> BlastRating:
    for threshold, rating in _RATING_THRESHOLDS:
        if total <= threshold:
            return rating
    return BlastRating.HIGH


def compute_blast_radii(
    findings: list[Finding],
    graph: CryptoDependencyGraph,
) -> list[BlastRadius]:
    """
    For each finding that has a corresponding node in the graph, compute how
    many other nodes would be affected if that finding's crypto is migrated.
    """
    # Build adjacency map: node_id → list of target node_ids
    adjacency: dict[str, list[str]] = defaultdict(list)
    for edge in graph.edges:
        adjacency[edge.source].append(edge.target)
        # Also traverse reverse direction (migration affects dependents too)
        adjacency[edge.target].append(edge.source)

    # Map finding ID → node ID(s) that represent it
    finding_to_nodes: dict[str, list[str]] = defaultdict(list)
    for node in graph.nodes:
        for fid in node.finding_ids:
            finding_to_nodes[fid].append(node.id)

    # All node IDs for quick set membership
    all_node_ids = {n.id for n in graph.nodes}

    results: list[BlastRadius] = []
    seen_findings: set[str] = set()

    for finding in findings:
        if finding.id in seen_findings:
            continue
        seen_findings.add(finding.id)

        source_nodes = finding_to_nodes.get(finding.id, [])
        if not source_nodes:
            # Finding has no graph node — still report a minimal blast radius
            results.append(
                BlastRadius(
                    finding_id=finding.id,
                    finding_title=finding.title,
                    direct_dependencies=[],
                    indirect_dependencies=[],
                    total_affected=0,
                    rating=BlastRating.LOW,
                    detail=(
                        "No graph node found for this finding — it may be isolated "
                        "or in a file with no other crypto relationships detected."
                    ),
                )
            )
            continue

        # BFS from each source node; collect unique visited nodes
        direct_deps: set[str] = set()
        indirect_deps: set[str] = set()
        visited: set[str] = set(source_nodes)
        queue: deque[tuple[str, int]] = deque()

        for sn in source_nodes:
            for neighbor in adjacency.get(sn, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    direct_deps.add(neighbor)
                    queue.append((neighbor, 1))

        while queue:
            node_id, depth = queue.popleft()
            for neighbor in adjacency.get(node_id, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    indirect_deps.add(neighbor)
                    queue.append((neighbor, depth + 1))

        # Exclude the source nodes themselves and the app root
        direct_deps -= set(source_nodes) | {"app::root"}
        indirect_deps -= set(source_nodes) | direct_deps | {"app::root"}
        total = len(direct_deps) + len(indirect_deps)
        rating = _rate(total)

        results.append(
            BlastRadius(
                finding_id=finding.id,
                finding_title=finding.title,
                direct_dependencies=sorted(direct_deps),
                indirect_dependencies=sorted(indirect_deps),
                total_affected=total,
                rating=rating,
                detail=_detail(rating, total, len(direct_deps), len(indirect_deps)),
            )
        )

    return results


def _detail(rating: BlastRating, total: int, direct: int, indirect: int) -> str:
    if rating == BlastRating.HIGH:
        urgency = "High blast radius — migrating this asset would likely require coordinated changes across multiple services/files."
    elif rating == BlastRating.MEDIUM:
        urgency = "Medium blast radius — plan for a moderate number of dependent changes."
    else:
        urgency = "Low blast radius — migration impact appears well-contained."
    return (
        f"{urgency} "
        f"Direct dependents: {direct}, indirect (transitive): {indirect}, total affected graph nodes: {total}. "
        f"Relationships are heuristically derived from static analysis."
    )
