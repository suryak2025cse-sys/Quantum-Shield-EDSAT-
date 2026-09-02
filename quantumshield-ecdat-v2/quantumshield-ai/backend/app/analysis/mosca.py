"""
Mosca's Inequality
===================
Introduced by Michele Mosca (2015): an asset using quantum-vulnerable
cryptography is AT RISK today if

    X + Y > Z

where
    X = "shelf life" — how many years the protected data must remain
        confidential (data security lifetime)
    Y = "migration time" — how many years it will take the organization to
        actually migrate this system to a quantum-safe algorithm
    Z = "threat timeline" — how many years until a cryptographically
        relevant quantum computer (CRQC) is expected to exist

The logic: if X + Y > Z, then the data will *still* need protection, or the
system will *still* be mid-migration, by the time a CRQC arrives — meaning
today's decision to delay migration is itself the risk. This is exactly the
formal backbone the QT-3.6 problem statement asks for; a boolean
"harvest-now-risk" flag (which is what earlier versions of this scanner used)
is a simplification of this, not the same thing.

This module doesn't try to *automatically know* the true X and Y for a given
organization — no static scanner can (X depends on data-retention policy, Y
on engineering capacity). Instead it:
  1. Provides sane, documented default heuristics per artifact category, so
     the tool is usable out of the box.
  2. Accepts an optional per-scan MoscaConfig so an organization can override
     the threat horizon (Z) and category-level (X, Y) defaults with real
     figures from their own risk register.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.models.schemas import Category, MoscaAssessment, MoscaRiskLevel

# ---------------------------------------------------------------------------
# Default assumptions (all in years). These are documented, editable
# starting points — NOT a substitute for an organization's own data
# classification and migration-capacity estimates.
# ---------------------------------------------------------------------------

# Z — industry estimates for CRQC arrival vary widely (roughly 2030-2040+ in
# most public expert surveys as of this writing). We default to a
# conservative middle estimate and make it fully overridable.
DEFAULT_QUANTUM_THREAT_HORIZON_YEARS = 10.0

# X — data security lifetime, by rough context inferred from category/path.
# These mirror commonly cited retention periods (e.g. financial records,
# health records) and should be treated as illustrative defaults.
DEFAULT_DATA_LIFETIME_BY_HINT = {
    "health": 20.0,
    "medical": 20.0,
    "patient": 20.0,
    "government": 25.0,
    "defense": 25.0,
    "classified": 25.0,
    "financial": 10.0,
    "payment": 10.0,
    "billing": 10.0,
    "auth": 5.0,
    "session": 0.25,
    "token": 0.25,
    "cache": 0.1,
}
DEFAULT_DATA_LIFETIME_FALLBACK = 5.0  # generic "sensitive business data" default

# Y — migration time, by how deeply embedded the artifact tends to be.
DEFAULT_MIGRATION_TIME_BY_CATEGORY = {
    Category.CERTIFICATE_ISSUE: 1.5,          # cert rotation is comparatively fast
    Category.QUANTUM_VULNERABLE_CRYPTO: 2.5,  # code-level algorithm swap + testing
    Category.HSM_CLOUD_KMS: 3.0,              # hardware/vendor dependent, slower
    Category.CRYPTO_LIBRARY: 2.0,
    Category.CLASSICAL_CRYPTO_WEAKNESS: 1.0,
}
DEFAULT_MIGRATION_TIME_FALLBACK = 2.0

WATCH_BUFFER_YEARS = 2.0  # how close to the threshold counts as "watch" not "safe"


@dataclass
class MoscaConfig:
    """Per-scan overrides. All optional — falls back to the documented defaults above."""
    quantum_threat_horizon_years: float = DEFAULT_QUANTUM_THREAT_HORIZON_YEARS
    data_lifetime_overrides: dict[str, float] = field(default_factory=dict)
    migration_time_overrides: dict[str, float] = field(default_factory=dict)


def _infer_data_lifetime(file_path: str, config: MoscaConfig) -> tuple[float, str]:
    path_lower = file_path.lower()
    for hint, years in {**DEFAULT_DATA_LIFETIME_BY_HINT, **config.data_lifetime_overrides}.items():
        if hint in path_lower:
            return years, f"inferred from path containing '{hint}'"
    return DEFAULT_DATA_LIFETIME_FALLBACK, "generic default (no path hint matched)"


def _infer_migration_time(category: Category, config: MoscaConfig) -> tuple[float, str]:
    override = config.migration_time_overrides.get(category.value)
    if override is not None:
        return override, "organization-provided override"
    years = DEFAULT_MIGRATION_TIME_BY_CATEGORY.get(category, DEFAULT_MIGRATION_TIME_FALLBACK)
    return years, "default estimate for this artifact category"


QUANTUM_VULNERABLE_CATEGORIES = {
    Category.QUANTUM_VULNERABLE_CRYPTO,
    Category.CERTIFICATE_ISSUE,
    Category.HSM_CLOUD_KMS,
}


def assess(category: Category, file_path: str, is_quantum_vulnerable: bool, config: MoscaConfig | None = None) -> MoscaAssessment | None:
    """Compute a Mosca assessment for a single finding. Returns None if the
    finding isn't a quantum-relevant artifact (e.g. a hardcoded secret has no
    Mosca timeline — it's exploitable today regardless of quantum progress)."""
    if not is_quantum_vulnerable:
        return None

    cfg = config or MoscaConfig()
    x, x_reason = _infer_data_lifetime(file_path, cfg)
    y, y_reason = _infer_migration_time(category, cfg)
    z = cfg.quantum_threat_horizon_years
    total = x + y

    if total > z:
        level = MoscaRiskLevel.AT_RISK
    elif total > z - WATCH_BUFFER_YEARS:
        level = MoscaRiskLevel.WATCH
    else:
        level = MoscaRiskLevel.SAFE

    rationale = (
        f"X (data lifetime) = {x:g}y ({x_reason}); "
        f"Y (migration time) = {y:g}y ({y_reason}); "
        f"X+Y = {total:g}y vs. Z (quantum threat horizon) = {z:g}y \u2192 "
        + {
            MoscaRiskLevel.AT_RISK: "X+Y exceeds Z: this asset will still need protection, or still be mid-migration, when a CRQC is expected.",
            MoscaRiskLevel.WATCH: "X+Y is within the buffer of Z: safe today under these assumptions, but close enough to warrant monitoring.",
            MoscaRiskLevel.SAFE: "X+Y is comfortably under Z given current assumptions.",
        }[level]
    )

    return MoscaAssessment(
        data_lifetime_years=x,
        migration_time_years=y,
        quantum_threat_horizon_years=z,
        x_plus_y=total,
        risk_level=level,
        rationale=rationale,
    )
