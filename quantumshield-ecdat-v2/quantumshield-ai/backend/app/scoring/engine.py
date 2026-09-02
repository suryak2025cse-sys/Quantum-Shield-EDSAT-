"""
Risk Scoring Engine
====================
Converts a flat list of Findings into the headline scores shown on the
executive dashboard. Two scores matter most:

  Security Score          -> "how exposed are we to attackers TODAY"
  Quantum Readiness Score  -> "how exposed are we once CRQCs exist"

Both are computed as a severity-weighted deduction from 100, with
diminishing returns (sqrt dampening) so that one repo with 200 low-severity
lint-style issues doesn't score worse than one repo with 3 critical RCEs.
This mirrors how real product scoring engines (e.g. Qualys, Snyk Health
Score) avoid "finding-count spam" dominating the signal.
"""
from __future__ import annotations

import math
from collections import Counter

from app.models.schemas import Category, Finding, ScoreBreakdown, Severity

# Severity -> point deduction weight (before dampening)
SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 12.0,
    Severity.HIGH: 6.0,
    Severity.MEDIUM: 3.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.25,
}

QUANTUM_CATEGORIES = {Category.QUANTUM_VULNERABLE_CRYPTO, Category.CERTIFICATE_ISSUE}
CLASSICAL_CATEGORIES = {
    Category.SECRET,
    Category.CLASSICAL_CRYPTO_WEAKNESS,
    Category.AUTH_WEAKNESS,
    Category.DEPENDENCY_CVE,
    Category.INSECURE_CONFIG,
    Category.CERTIFICATE_ISSUE,
    Category.CRYPTO_LIBRARY,
    Category.HSM_CLOUD_KMS,
    Category.BINARY_ARTIFACT,
}


def _dampened_deduction(findings: list[Finding]) -> float:
    """Sum severity weights with sqrt dampening on finding count per severity
    bucket, so repeated low-value findings don't linearly crater the score."""
    by_severity: dict[Severity, int] = Counter(f.severity for f in findings)
    deduction = 0.0
    for severity, count in by_severity.items():
        weight = SEVERITY_WEIGHTS[severity]
        # sqrt(count) dampens repeat findings of the same severity
        deduction += weight * math.sqrt(count)
    return deduction


def compute_security_score(findings: list[Finding]) -> float:
    classical = [f for f in findings if f.category in CLASSICAL_CATEGORIES]
    score = 100.0 - _dampened_deduction(classical)
    return round(max(0.0, min(100.0, score)), 1)


def compute_quantum_readiness_score(findings: list[Finding]) -> float:
    quantum = [f for f in findings if f.category in QUANTUM_CATEGORIES or f.quantum_harvest_now_risk]
    score = 100.0 - _dampened_deduction(quantum) * 1.15  # quantum risk weighted slightly higher: fix window is long
    # Extra penalty for "harvest now, decrypt later" exposure — data with a long
    # confidentiality shelf-life encrypted with quantum-vulnerable crypto today.
    harvest_risk_count = sum(1 for f in quantum if f.quantum_harvest_now_risk)
    score -= min(15.0, harvest_risk_count * 1.5)
    return round(max(0.0, min(100.0, score)), 1)


def compute_criticality_score(findings: list[Finding]) -> float:
    """% of findings that are CRITICAL or HIGH — signals urgency, not just volume."""
    if not findings:
        return 100.0
    urgent = sum(1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
    ratio = urgent / len(findings)
    return round(max(0.0, 100.0 - ratio * 100.0), 1)


def compute_compliance_score(findings: list[Finding]) -> float:
    """Approximates alignment with common frameworks (PCI-DSS, SOC 2, NIST 800-53,
    and NIST's PQC migration guidance CNSA 2.0 / NSM-10). Hardcoded secrets and
    weak crypto are direct control failures under nearly all of these."""
    weight_map = {
        Category.SECRET: 8.0,
        Category.CERTIFICATE_ISSUE: 5.0,
        Category.CLASSICAL_CRYPTO_WEAKNESS: 4.0,
        Category.QUANTUM_VULNERABLE_CRYPTO: 3.0,  # not yet mandatory for most frameworks, but CNSA 2.0 timelines apply
        Category.AUTH_WEAKNESS: 6.0,
        Category.DEPENDENCY_CVE: 4.0,
        Category.INSECURE_CONFIG: 3.0,
    }
    deduction = 0.0
    by_cat: dict[Category, int] = Counter(f.category for f in findings)
    for cat, count in by_cat.items():
        deduction += weight_map.get(cat, 2.0) * math.sqrt(count)
    return round(max(0.0, min(100.0, 100.0 - deduction)), 1)


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def compute_scores(findings: list[Finding], previous_overall: float | None = None) -> ScoreBreakdown:
    security = compute_security_score(findings)
    quantum = compute_quantum_readiness_score(findings)
    criticality = compute_criticality_score(findings)
    compliance = compute_compliance_score(findings)

    # Overall health: security weighted highest (today's risk is most urgent),
    # quantum readiness second (strategic risk), then compliance/criticality as modifiers.
    overall = round(security * 0.40 + quantum * 0.30 + compliance * 0.20 + criticality * 0.10, 1)

    if previous_overall is None:
        trend = "stable"
    elif overall > previous_overall + 1.0:
        trend = "improving"
    elif overall < previous_overall - 1.0:
        trend = "declining"
    else:
        trend = "stable"

    return ScoreBreakdown(
        security_score=security,
        quantum_readiness_score=quantum,
        criticality_score=criticality,
        compliance_score=compliance,
        overall_health=overall,
        risk_trend=trend,
        grade=_grade(overall),
    )
