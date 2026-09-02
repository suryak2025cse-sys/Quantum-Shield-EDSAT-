"""
Mosca's Inequality & Quantum Threat Assessment
================================================
Evaluates Mosca's theorem:

    X + Y > Z

where:
    X = Data Security Lifetime (years data must remain confidential)
    Y = Migration Duration (years required to transition system to PQC)
    Z = Quantum Threat Horizon (estimated years until a CRQC is operational)

Provides:
  - Global and per-asset assessment
  - Multi-horizon sensitivity analysis (Z = 5, 10, 15, 20 years)
  - Clear rationale and confidence indicators
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models.schemas import Category, MoscaAssessment, MoscaRiskLevel

DEFAULT_QUANTUM_THREAT_HORIZON_YEARS = 10.0

DEFAULT_DATA_LIFETIME_BY_HINT = {
    "health": 20.0,
    "medical": 20.0,
    "patient": 20.0,
    "government": 25.0,
    "defense": 25.0,
    "classified": 25.0,
    "vault": 20.0,
    "kms": 15.0,
    "secret": 15.0,
    "financial": 10.0,
    "payment": 10.0,
    "billing": 10.0,
    "pii": 10.0,
    "auth": 5.0,
    "login": 5.0,
    "session": 0.25,
    "token": 0.25,
    "test": 0.1,
    "sample": 0.1,
}
DEFAULT_DATA_LIFETIME_FALLBACK = 5.0

DEFAULT_MIGRATION_TIME_BY_CATEGORY = {
    Category.CERTIFICATE_ISSUE: 1.5,
    Category.QUANTUM_VULNERABLE_CRYPTO: 2.5,
    Category.HSM_CLOUD_KMS: 3.5,
    Category.CRYPTO_LIBRARY: 2.0,
    Category.CLASSICAL_CRYPTO_WEAKNESS: 1.0,
    Category.AUTH_WEAKNESS: 0.5,
}
DEFAULT_MIGRATION_TIME_FALLBACK = 2.0
WATCH_BUFFER_YEARS = 2.0


@dataclass
class MoscaConfig:
    quantum_threat_horizon_years: float = DEFAULT_QUANTUM_THREAT_HORIZON_YEARS
    data_lifetime_overrides: dict[str, float] = field(default_factory=dict)
    migration_time_overrides: dict[str, float] = field(default_factory=dict)


def compute_sensitivity_matrix(x: float, y: float, horizons: list[float] | None = None) -> dict[str, Any]:
    """Computes Mosca risk level across multiple quantum threat timelines (Z)."""
    if horizons is None:
        horizons = [5.0, 7.0, 10.0, 15.0, 20.0]

    total = x + y
    matrix = {}
    for z in horizons:
        if total > z:
            status = "AT_RISK"
        elif total > z - WATCH_BUFFER_YEARS:
            status = "WATCH"
        else:
            status = "SAFE"
        matrix[f"Z={z:g}y"] = {
            "threat_horizon_years": z,
            "x_plus_y_years": total,
            "status": status,
            "breach_gap_years": round(total - z, 1),
        }
    return matrix


def _infer_data_lifetime(file_path: str, config: MoscaConfig) -> tuple[float, str]:
    path_lower = file_path.lower()
    for hint, years in {**DEFAULT_DATA_LIFETIME_BY_HINT, **config.data_lifetime_overrides}.items():
        if hint in path_lower:
            return years, f"path hint '{hint}'"
    return DEFAULT_DATA_LIFETIME_FALLBACK, "default baseline lifetime"


def _infer_migration_time(category: Category, config: MoscaConfig) -> tuple[float, str]:
    override = config.migration_time_overrides.get(category.value)
    if override is not None:
        return override, "user configuration override"
    years = DEFAULT_MIGRATION_TIME_BY_CATEGORY.get(category, DEFAULT_MIGRATION_TIME_FALLBACK)
    return years, f"standard migration window for {category.value}"


QUANTUM_VULNERABLE_CATEGORIES = {
    Category.QUANTUM_VULNERABLE_CRYPTO,
    Category.CERTIFICATE_ISSUE,
    Category.HSM_CLOUD_KMS,
}


def assess(
    category: Category,
    file_path: str,
    is_quantum_vulnerable: bool,
    config: MoscaConfig | None = None,
    explicit_x: float | None = None,
    explicit_y: float | None = None,
) -> MoscaAssessment | None:
    """Computes Mosca's inequality assessment for a quantum-vulnerable asset."""
    if not is_quantum_vulnerable:
        return None

    cfg = config or MoscaConfig()
    x, x_reason = (explicit_x, "explicit asset metadata") if explicit_x is not None else _infer_data_lifetime(file_path, cfg)
    y, y_reason = (explicit_y, "explicit asset metadata") if explicit_y is not None else _infer_migration_time(category, cfg)
    z = cfg.quantum_threat_horizon_years
    total = x + y

    if total > z:
        level = MoscaRiskLevel.AT_RISK
    elif total > z - WATCH_BUFFER_YEARS:
        level = MoscaRiskLevel.WATCH
    else:
        level = MoscaRiskLevel.SAFE

    gap = total - z
    if level == MoscaRiskLevel.AT_RISK:
        explanation = f"X+Y exceeds Z by {gap:.1f} years: data exposure will occur before migration finishes when CRQC emerges."
    elif level == MoscaRiskLevel.WATCH:
        explanation = f"X+Y is within {WATCH_BUFFER_YEARS}y buffer of Z: borderline exposure risk requiring active migration scheduling."
    else:
        explanation = f"X+Y is comfortably below Z ({total:.1f}y < {z:.1f}y) under current threat assumptions."

    rationale = f"X={x:g}y ({x_reason}) + Y={y:g}y ({y_reason}) = {total:g}y vs Z={z:g}y -> {explanation}"

    return MoscaAssessment(
        data_lifetime_years=x,
        migration_time_years=y,
        quantum_threat_horizon_years=z,
        x_plus_y=total,
        risk_level=level,
        rationale=rationale,
    )
