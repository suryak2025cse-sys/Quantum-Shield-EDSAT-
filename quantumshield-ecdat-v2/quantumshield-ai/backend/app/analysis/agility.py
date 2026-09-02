"""
Crypto-Agility Difficulty Scorer
==================================
Estimates how hard it will be to migrate the cryptographic assets found in
a codebase to post-quantum equivalents. Produces an `AgilityScore` with:

  score   0-100  (0 = trivially easy, 100 = extremely hard)
  label   Easy / Moderate / Difficult
  factors — per-factor breakdown so results are explainable

Factors (all are heuristic estimates from static analysis; labeled as such):

  F1. CRYPTO_USAGE_DENSITY
      Total number of unique crypto usages (findings). More usages = more
      migration touch-points = higher difficulty.

  F2. HARDCODED_VS_ABSTRACTED
      Ratio of findings that are inline hardcoded patterns vs. findings in
      library/config files. High inline ratio → tightly coupled, harder.

  F3. AFFECTED_FILES
      Unique file count. Spreading crypto across many files increases the
      migration surface area.

  F4. FILE_CATEGORY_COUPLING
      Unique (file, category) pairs — signals how many distinct categories
      of crypto problem appear per file rather than being concentrated.

  F5. BLOCKERS
      Count of findings in categories known to slow migration:
      HSM/KMS (vendor lock-in), DEPENDENCY_CVE (third-party), BINARY_ARTIFACT.

  F6. QUANTUM_FINDINGS_RATIO
      Proportion of findings that are quantum-vulnerable (need PQC migration,
      not just a classical fix). PQC migration is widely considered harder
      than classical upgrades because standards are newer and tooling is sparse.

Weights are calibrated so a typical small project with a few RSA usages
scores "Easy", a medium-sized project where crypto appears in many files
scores "Moderate", and a large enterprise project with HSM dependencies
and many quantum-vulnerable usages scores "Difficult".
"""
from __future__ import annotations

import math
from collections import Counter

from app.models.schemas import (
    AgilityFactorDetail,
    AgilityLabel,
    AgilityScore,
    Category,
    Finding,
)

# Weight of each factor's contribution toward the 0-100 score
FACTOR_WEIGHTS = {
    "CRYPTO_USAGE_DENSITY":    20.0,
    "HARDCODED_VS_ABSTRACTED": 20.0,
    "AFFECTED_FILES":          15.0,
    "FILE_CATEGORY_COUPLING":  10.0,
    "BLOCKERS":                15.0,
    "QUANTUM_FINDINGS_RATIO":  20.0,
}

# Categories that signal harder-to-migrate assets
BLOCKER_CATEGORIES = {
    Category.HSM_CLOUD_KMS,
    Category.DEPENDENCY_CVE,
    Category.BINARY_ARTIFACT,
}

QUANTUM_CATEGORIES = {
    Category.QUANTUM_VULNERABLE_CRYPTO,
    Category.CERTIFICATE_ISSUE,
}

ABSTRACTED_EXTENSION_HINTS = {".json", ".yaml", ".yml", ".toml", ".cfg", ".conf", ".env"}


def _pct(raw: float, max_val: float) -> float:
    """Normalize raw value to [0, 100] capped at max_val."""
    return min(100.0, (raw / max_val) * 100.0) if max_val > 0 else 0.0


def compute_agility_score(findings: list[Finding]) -> AgilityScore:
    """Compute the crypto-agility difficulty score from a list of findings."""
    if not findings:
        return AgilityScore(
            score=0.0,
            label=AgilityLabel.EASY,
            factors=[],
            explanation=(
                "No cryptographic findings detected — this project has no "
                "measurable crypto migration burden."
            ),
        )

    # Pre-compute collections
    unique_files = {f.file_path for f in findings}
    file_cat_pairs = {(f.file_path, f.category) for f in findings}
    blocker_count = sum(1 for f in findings if f.category in BLOCKER_CATEGORIES)
    quantum_count = sum(1 for f in findings if f.category in QUANTUM_CATEGORIES or f.quantum_harvest_now_risk)

    # --- F1: Crypto usage density ---
    n = len(findings)
    # Logarithmic scale: 50+ usages → full weight; 5 → ~50%
    f1_raw = _pct(math.log1p(n) / math.log1p(50), 1.0)
    f1 = AgilityFactorDetail(
        name="CRYPTO_USAGE_DENSITY",
        value=n,
        weight=FACTOR_WEIGHTS["CRYPTO_USAGE_DENSITY"],
        contribution=round(f1_raw * FACTOR_WEIGHTS["CRYPTO_USAGE_DENSITY"] / 100, 2),
        note=f"{n} total crypto findings detected (logarithmic scale, 50+ = full weight).",
    )

    # --- F2: Hardcoded vs abstracted ---
    hardcoded_count = sum(
        1 for f in findings
        if not any(f.file_path.endswith(ext) for ext in ABSTRACTED_EXTENSION_HINTS)
        and f.category != Category.CRYPTO_LIBRARY
    )
    hardcoded_ratio = hardcoded_count / n if n else 0.0
    f2_raw = hardcoded_ratio * 100
    f2 = AgilityFactorDetail(
        name="HARDCODED_VS_ABSTRACTED",
        value=f"{hardcoded_count}/{n} hardcoded",
        weight=FACTOR_WEIGHTS["HARDCODED_VS_ABSTRACTED"],
        contribution=round(f2_raw * FACTOR_WEIGHTS["HARDCODED_VS_ABSTRACTED"] / 100, 2),
        note=(
            f"{hardcoded_ratio:.0%} of usages appear inline in source files "
            f"(vs. config/library files), hinting at tightly-coupled implementation."
        ),
    )

    # --- F3: Affected files ---
    num_files = len(unique_files)
    # 20+ files → full weight
    f3_raw = _pct(math.log1p(num_files) / math.log1p(20), 1.0)
    f3 = AgilityFactorDetail(
        name="AFFECTED_FILES",
        value=num_files,
        weight=FACTOR_WEIGHTS["AFFECTED_FILES"],
        contribution=round(f3_raw * FACTOR_WEIGHTS["AFFECTED_FILES"] / 100, 2),
        note=f"Crypto spread across {num_files} unique file(s).",
    )

    # --- F4: File-category coupling ---
    coupling = len(file_cat_pairs)
    # 10+ pairs → full weight
    f4_raw = _pct(coupling / 10, 1.0)
    f4 = AgilityFactorDetail(
        name="FILE_CATEGORY_COUPLING",
        value=coupling,
        weight=FACTOR_WEIGHTS["FILE_CATEGORY_COUPLING"],
        contribution=round(f4_raw * FACTOR_WEIGHTS["FILE_CATEGORY_COUPLING"] / 100, 2),
        note=f"{coupling} unique (file, category) pairs indicate the breadth of the migration surface.",
    )

    # --- F5: Blockers ---
    f5_raw = _pct(blocker_count / 5, 1.0)
    f5 = AgilityFactorDetail(
        name="BLOCKERS",
        value=blocker_count,
        weight=FACTOR_WEIGHTS["BLOCKERS"],
        contribution=round(f5_raw * FACTOR_WEIGHTS["BLOCKERS"] / 100, 2),
        note=(
            f"{blocker_count} finding(s) in HSM/KMS, dependency CVE, or binary categories "
            f"that typically require third-party coordination or hardware replacement."
        ),
    )

    # --- F6: Quantum findings ratio ---
    q_ratio = quantum_count / n if n else 0.0
    f6_raw = q_ratio * 100
    f6 = AgilityFactorDetail(
        name="QUANTUM_FINDINGS_RATIO",
        value=f"{quantum_count}/{n} quantum-vulnerable",
        weight=FACTOR_WEIGHTS["QUANTUM_FINDINGS_RATIO"],
        contribution=round(f6_raw * FACTOR_WEIGHTS["QUANTUM_FINDINGS_RATIO"] / 100, 2),
        note=(
            f"{q_ratio:.0%} of findings require PQC migration (NIST FIPS 203/204/205), "
            f"which is more complex than classical algorithm upgrades."
        ),
    )

    factors = [f1, f2, f3, f4, f5, f6]
    total_score = round(sum(fc.contribution for fc in factors), 1)
    total_score = max(0.0, min(100.0, total_score))

    if total_score <= 33:
        label = AgilityLabel.EASY
    elif total_score <= 66:
        label = AgilityLabel.MODERATE
    else:
        label = AgilityLabel.DIFFICULT

    explanation = _build_explanation(label, total_score, factors, n, num_files, blocker_count, quantum_count)

    return AgilityScore(
        score=total_score,
        label=label,
        factors=factors,
        explanation=explanation,
        is_heuristic=True,
    )


def _build_explanation(
    label: AgilityLabel,
    score: float,
    factors: list[AgilityFactorDetail],
    n_findings: int,
    n_files: int,
    blockers: int,
    quantum: int,
) -> str:
    top_factor = max(factors, key=lambda fc: fc.contribution)
    parts = [
        f"Migration difficulty: **{label.value}** (score {score}/100). ",
        f"Analysis based on {n_findings} finding(s) across {n_files} file(s). ",
    ]
    parts.append(
        f"Dominant factor: **{top_factor.name}** contributing {top_factor.contribution:.1f}/100 points. "
    )
    if blockers:
        parts.append(
            f"{blockers} finding(s) involve HSM/KMS, third-party dependencies, or compiled binaries "
            f"that require vendor coordination — these cannot be migrated by code change alone. "
        )
    if quantum:
        parts.append(
            f"{quantum} quantum-vulnerable finding(s) require NIST PQC standard algorithms "
            f"(ML-KEM FIPS 203, ML-DSA FIPS 204, or SLH-DSA FIPS 205). "
        )
    parts.append("All scores are heuristic estimates derived from static analysis.")
    return "".join(parts)
