"""
Business Criticality Classification
=====================================
Classifies each finding by business criticality so remediation can be
prioritized by impact, not just technical severity. Like the Mosca module,
this is heuristic-by-default (inferred from path/filename conventions) and
fully overridable via a classification config an organization supplies —
no static scanner can know an org's actual business context on its own.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from app.models.schemas import Criticality

# path-substring -> criticality, checked in order (first match wins)
DEFAULT_CRITICALITY_HINTS: list[tuple[str, Criticality]] = [
    ("payment", Criticality.CRITICAL),
    ("billing", Criticality.CRITICAL),
    ("checkout", Criticality.CRITICAL),
    ("auth", Criticality.CRITICAL),
    ("login", Criticality.CRITICAL),
    ("identity", Criticality.CRITICAL),
    ("secret", Criticality.CRITICAL),
    ("kms", Criticality.CRITICAL),
    ("vault", Criticality.CRITICAL),
    ("health", Criticality.HIGH),
    ("patient", Criticality.HIGH),
    ("pii", Criticality.HIGH),
    ("customer", Criticality.HIGH),
    ("admin", Criticality.HIGH),
    ("user", Criticality.MEDIUM),
    ("api", Criticality.MEDIUM),
    ("internal", Criticality.MEDIUM),
    ("test", Criticality.LOW),
    ("sample", Criticality.LOW),
    ("demo", Criticality.LOW),
    ("mock", Criticality.LOW),
    ("fixture", Criticality.LOW),
]
DEFAULT_CRITICALITY_FALLBACK = Criticality.MEDIUM


@dataclass
class ClassificationConfig:
    """Optional organization-provided overrides, loaded from a JSON file like:
    {
      "path_criticality": { "services/payments": "critical", "services/reporting": "low" },
      "default": "medium"
    }
    Override entries are checked before the built-in defaults.
    """
    path_overrides: dict[str, Criticality] = field(default_factory=dict)
    default: Criticality = DEFAULT_CRITICALITY_FALLBACK

    @classmethod
    def from_json_file(cls, path: str) -> "ClassificationConfig":
        data = json.loads(Path(path).read_text())
        overrides = {k: Criticality(v.lower()) for k, v in data.get("path_criticality", {}).items()}
        default = Criticality(data.get("default", "medium").lower())
        return cls(path_overrides=overrides, default=default)


def classify(file_path: str, config: ClassificationConfig | None = None) -> tuple[Criticality, str]:
    """Returns (criticality, reason) for a given file path."""
    cfg = config or ClassificationConfig()
    path_lower = file_path.lower()

    for hint, criticality in cfg.path_overrides.items():
        if hint.lower() in path_lower:
            return criticality, f"organization override: path contains '{hint}'"

    for hint, criticality in DEFAULT_CRITICALITY_HINTS:
        if hint in path_lower:
            return criticality, f"default heuristic: path contains '{hint}'"

    return cfg.default, "no path hint matched — default criticality applied"
