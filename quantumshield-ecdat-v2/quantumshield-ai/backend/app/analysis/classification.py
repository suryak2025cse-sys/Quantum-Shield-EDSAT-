"""
Business Criticality & Asset Classification
=============================================
Classifies findings and assets by business criticality, regulatory category,
data sensitivity, data lifetime, and exposure profile.

Supports:
  - Explicit user-provided metadata configuration (JSON profile)
  - Rule-based path and file heuristics as fallback defaults
  - Explicit confidence tagging ("User Configured" vs "Inferred Heuristic")
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.models.schemas import Criticality, Exposure

DEFAULT_CRITICALITY_HINTS: list[tuple[str, Criticality, str, float]] = [
    # (path_hint, criticality, sensitivity, default_x_lifetime)
    ("payment", Criticality.CRITICAL, "PCI-DSS Financial Data", 10.0),
    ("billing", Criticality.CRITICAL, "Financial & Invoicing Data", 10.0),
    ("checkout", Criticality.CRITICAL, "E-Commerce Transaction Data", 10.0),
    ("auth", Criticality.CRITICAL, "Authentication & Session Tokens", 5.0),
    ("login", Criticality.CRITICAL, "User Credentials", 5.0),
    ("identity", Criticality.CRITICAL, "IAM / Identity Provider", 10.0),
    ("secret", Criticality.CRITICAL, "Cryptographic Secrets & Master Keys", 15.0),
    ("kms", Criticality.CRITICAL, "Key Management Service Infrastructure", 20.0),
    ("vault", Criticality.CRITICAL, "Secrets Vault & PKI Roots", 25.0),
    ("health", Criticality.HIGH, "HIPAA Electronic Protected Health Info (ePHI)", 20.0),
    ("patient", Criticality.HIGH, "Patient Healthcare Records", 20.0),
    ("pii", Criticality.HIGH, "GDPR Personally Identifiable Info", 10.0),
    ("customer", Criticality.HIGH, "Customer Account Data", 7.0),
    ("admin", Criticality.HIGH, "Privileged Administrative Interface", 5.0),
    ("user", Criticality.MEDIUM, "Standard User Application Context", 5.0),
    ("api", Criticality.MEDIUM, "Application Programming Interface", 3.0),
    ("internal", Criticality.MEDIUM, "Internal Microservice Communication", 3.0),
    ("test", Criticality.LOW, "Test Fixture / Non-Production", 0.1),
    ("sample", Criticality.LOW, "Sample / Demonstration Code", 0.1),
    ("demo", Criticality.LOW, "Demo Scenario", 0.1),
    ("mock", Criticality.LOW, "Mock Interface", 0.1),
    ("fixture", Criticality.LOW, "Testing Fixture", 0.1),
]

DEFAULT_CRITICALITY_FALLBACK = Criticality.MEDIUM


@dataclass
class AssetMetadataProfile:
    business_owner: str | None = None
    application_name: str | None = None
    data_type: str | None = None
    data_sensitivity: str | None = None
    criticality: Criticality | None = None
    regulatory_category: str | None = None
    data_lifetime_years: float | None = None
    cryptoperiod_years: float | None = None
    exposure: Exposure | None = None
    migration_deadline: str | None = None


@dataclass
class ClassificationConfig:
    """Organization-provided classification map loaded from JSON."""
    path_overrides: dict[str, Criticality] = field(default_factory=dict)
    asset_profiles: dict[str, AssetMetadataProfile] = field(default_factory=dict)
    default_criticality: Criticality = DEFAULT_CRITICALITY_FALLBACK
    default_owner: str = "Engineering / Security Team"

    @classmethod
    def from_json_file(cls, path: str) -> "ClassificationConfig":
        data = json.loads(Path(path).read_text(errors="ignore"))
        path_overrides = {k: Criticality(v.lower()) for k, v in data.get("path_criticality", {}).items()}

        profiles = {}
        for p_key, p_val in data.get("asset_profiles", {}).items():
            profiles[p_key] = AssetMetadataProfile(
                business_owner=p_val.get("business_owner"),
                application_name=p_val.get("application_name"),
                data_type=p_val.get("data_type"),
                data_sensitivity=p_val.get("data_sensitivity"),
                criticality=Criticality(p_val["criticality"].lower()) if "criticality" in p_val else None,
                regulatory_category=p_val.get("regulatory_category"),
                data_lifetime_years=float(p_val["data_lifetime_years"]) if "data_lifetime_years" in p_val else None,
                cryptoperiod_years=float(p_val["cryptoperiod_years"]) if "cryptoperiod_years" in p_val else None,
                exposure=Exposure(p_val["exposure"].lower()) if "exposure" in p_val else None,
                migration_deadline=p_val.get("migration_deadline"),
            )

        default_crit = Criticality(data.get("default", "medium").lower())
        return cls(path_overrides=path_overrides, asset_profiles=profiles, default_criticality=default_crit)


def classify(file_path: str, config: ClassificationConfig | None = None) -> tuple[Criticality, str]:
    """Returns (criticality, reason) for a given file path."""
    cfg = config or ClassificationConfig()
    path_lower = file_path.lower()

    # 1. Profile overrides
    for pattern, profile in cfg.asset_profiles.items():
        if pattern.lower() in path_lower and profile.criticality:
            return profile.criticality, f"user profile override: '{pattern}' (Owner: {profile.business_owner or 'Defined'})"

    # 2. Simple path overrides
    for hint, criticality in cfg.path_overrides.items():
        if hint.lower() in path_lower:
            return criticality, f"organization override: path contains '{hint}'"

    # 3. Built-in heuristics
    for hint, criticality, sensitivity, _ in DEFAULT_CRITICALITY_HINTS:
        if hint in path_lower:
            return criticality, f"default heuristic: path contains '{hint}' ({sensitivity})"

    return cfg.default_criticality, "default baseline criticality (no pattern matched)"
