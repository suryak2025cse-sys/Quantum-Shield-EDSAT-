"""
Related Findings / Approximate Blast Radius Heuristic
======================================================
Groups findings by shared signals:
  1. Same file (file_path)
  2. Same directory (parent directory of file_path)
  3. Same matched algorithm or library (matched_pattern, nist_pqc_recommendation, or category)
  4. Same certificate subject (extra subject/subject_cn fields)

NOT a real call-graph or runtime dependency trace — explicitly marked as a static heuristic.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from app.models.schemas import Finding, RelatedFinding

DISCLAIMER_TEXT = (
    "Related by shared file/algorithm — not a verified dependency trace. "
    "A full blast-radius analysis would require call-graph analysis, which this scanner does not perform."
)


def _extract_algo_key(f: Finding) -> str | None:
    if f.matched_pattern:
        return f.matched_pattern.upper()
    if f.nist_pqc_recommendation:
        return f.nist_pqc_recommendation.upper()
    if f.extra and isinstance(f.extra, dict):
        if "algorithm" in f.extra:
            return str(f.extra["algorithm"]).upper()
        if "library_name" in f.extra:
            return str(f.extra["library_name"]).upper()
    return None


def _extract_cert_subject(f: Finding) -> str | None:
    if f.extra and isinstance(f.extra, dict):
        subject = f.extra.get("subject") or f.extra.get("subject_cn") or f.extra.get("issuer")
        if subject:
            return str(subject).strip().lower()
    return None


def find_related_findings(finding: Finding, all_findings: list[Finding]) -> list[RelatedFinding]:
    """
    Finds findings in all_findings related to `finding` by heuristic co-occurrence signals.
    Excludes `finding` itself.
    """
    results: list[RelatedFinding] = []

    target_file = finding.file_path
    target_dir = str(Path(target_file).parent) if target_file else ""
    target_algo = _extract_algo_key(finding)
    target_cert_subject = _extract_cert_subject(finding)

    for other in all_findings:
        if other.id == finding.id:
            continue

        reasons: list[str] = []

        # 1. Same file
        if target_file and other.file_path == target_file:
            reasons.append(f"Same file ({target_file})")
        # 2. Same directory (if not same file)
        elif target_dir and str(Path(other.file_path).parent) == target_dir:
            reasons.append(f"Same directory ({target_dir})")

        # 3. Same matched algorithm / library
        other_algo = _extract_algo_key(other)
        if target_algo and other_algo:
            if target_algo == other_algo or target_algo in other_algo or other_algo in target_algo:
                reasons.append(f"Shared algorithm/library ({other_algo})")
        elif finding.category == other.category and finding.category.value in ("quantum_vulnerable_crypto", "classical_crypto_weakness", "crypto_library"):
            reasons.append(f"Same category ({finding.category.value})")

        # 4. Same certificate subject
        other_cert_subject = _extract_cert_subject(other)
        if target_cert_subject and other_cert_subject and target_cert_subject == other_cert_subject:
            reasons.append(f"Same certificate subject ({other_cert_subject})")

        if reasons:
            results.append(
                RelatedFinding(
                    id=other.id,
                    title=other.title,
                    severity=other.severity.value,
                    category=other.category.value,
                    file_path=other.file_path,
                    relationship_reasons=reasons,
                )
            )

    return results
