"""
QuantumShield AI — Core data models
Every scanner emits Finding objects in this shape so the scoring engine,
AI advisor, and report generator can stay decoupled from scanner internals.

Extended (v0.2.0) with models for:
  - CryptoDependencyGraph
  - AgilityScore (crypto-agility difficulty)
  - BlastRadius (migration impact)
  - PQCValidationResult
  - RemediationPlan (phased)
  - MigrationTicket
  - CICDPolicyResult
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    SECRET = "secret"
    CLASSICAL_CRYPTO_WEAKNESS = "classical_crypto_weakness"   # e.g. MD5, SHA1, weak TLS
    QUANTUM_VULNERABLE_CRYPTO = "quantum_vulnerable_crypto"    # e.g. RSA, ECC, DH
    AUTH_WEAKNESS = "auth_weakness"                            # JWT alg=none, weak sessions
    DEPENDENCY_CVE = "dependency_cve"
    INSECURE_CONFIG = "insecure_config"
    CERTIFICATE_ISSUE = "certificate_issue"
    CRYPTO_LIBRARY = "crypto_library"          # a library/dependency that implements crypto
    HSM_CLOUD_KMS = "hsm_cloud_kms"            # hardware/cloud key-management usage
    BINARY_ARTIFACT = "binary_artifact"        # crypto found in a compiled binary


class ArtifactType(str, Enum):
    """CBOM asset type — mirrors CycloneDX cryptoProperties.assetType."""
    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    RELATED_MATERIAL = "related-material"   # keys, secrets
    LIBRARY = "library"                     # not a native CycloneDX crypto assetType;
                                             # exported as a normal CycloneDX "library" component instead


class Criticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Exposure(str, Enum):
    EXTERNAL = "external"      # reachable from outside the org (Dockerfile EXPOSE, k8s Ingress/LoadBalancer)
    INTERNAL = "internal"      # only internal signals found (e.g. ClusterIP)
    UNKNOWN = "unknown"        # no infra manifest evidence either way — heuristic default


class MoscaRiskLevel(str, Enum):
    """
    Mosca's inequality: an asset is AT RISK if
        X (data security lifetime) + Y (migration time) > Z (years until a
        cryptographically relevant quantum computer, CRQC, is expected)
    i.e. the data will still need to be confidential, or the system will still
    be mid-migration, by the time quantum computers can break it.
    """
    AT_RISK = "at_risk"
    WATCH = "watch"          # within a configurable buffer of the threshold
    SAFE = "safe"
    NOT_APPLICABLE = "not_applicable"   # asset isn't quantum-vulnerable to begin with


class MoscaAssessment(BaseModel):
    data_lifetime_years: float
    migration_time_years: float
    quantum_threat_horizon_years: float   # Z, years from now
    x_plus_y: float
    risk_level: MoscaRiskLevel
    rationale: str


class Finding(BaseModel):
    id: str
    category: Category
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    matched_pattern: Optional[str] = None
    cwe_id: Optional[str] = None          # e.g. "CWE-327"
    nist_pqc_recommendation: Optional[str] = None  # e.g. "ML-KEM (Kyber)"
    quantum_harvest_now_risk: bool = False  # "harvest now, decrypt later" exposure
    ai_explanation: Optional[str] = None
    remediation: Optional[str] = None
    detected_at: datetime = Field(default_factory=datetime.utcnow)

    # --- CBOM / classification extensions ---
    artifact_type: ArtifactType = ArtifactType.ALGORITHM
    criticality: Optional[Criticality] = None
    exposure: Exposure = Exposure.UNKNOWN
    mosca: Optional[MoscaAssessment] = None
    # extra structured detail per artifact type (cert fields, algorithm params, etc.)
    extra: dict = Field(default_factory=dict)


class ScoreBreakdown(BaseModel):
    security_score: float          # 0-100
    quantum_readiness_score: float  # 0-100
    criticality_score: float
    compliance_score: float
    overall_health: float
    risk_trend: str                 # "improving" | "stable" | "declining"
    grade: str                      # A / B / C / D / F


# ScanSummary definition moved below v0.2.0 models



# ==========================================================================
# v0.2.0 — Dependency Graph
# ==========================================================================

class NodeType(str, Enum):
    ALGORITHM  = "algorithm"
    KEY        = "key"
    CERTIFICATE = "certificate"
    SERVICE    = "service"
    LIBRARY    = "library"
    APPLICATION = "application"
    FILE       = "file"


class DependencyNode(BaseModel):
    id: str
    node_type: NodeType
    label: str
    severity: Optional[str] = None        # from associated finding
    criticality: Optional[str] = None
    mosca_risk: Optional[str] = None
    finding_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DependencyEdge(BaseModel):
    source: str     # node id
    target: str     # node id
    relationship: str  # e.g. "uses", "signs", "depends-on", "contained-in"
    heuristic: bool = True  # flag: relationship inferred statically, not observed at runtime


class CryptoDependencyGraph(BaseModel):
    nodes: list[DependencyNode] = Field(default_factory=list)
    edges: list[DependencyEdge] = Field(default_factory=list)
    note: str = ("Relationships are heuristically inferred from static analysis "
                 "and may not reflect all runtime connections.")


# ==========================================================================
# v0.2.0 — Crypto-Agility Score
# ==========================================================================

class AgilityLabel(str, Enum):
    EASY     = "Easy"
    MODERATE = "Moderate"
    DIFFICULT = "Difficult"


class AgilityFactorDetail(BaseModel):
    name: str
    value: Any
    weight: float
    contribution: float   # 0-100 portion this factor added to score
    note: str


class AgilityScore(BaseModel):
    score: float                      # 0-100  (higher = harder to migrate)
    label: AgilityLabel
    factors: list[AgilityFactorDetail]
    explanation: str
    is_heuristic: bool = True


# ==========================================================================
# v0.2.0 — Blast Radius
# ==========================================================================

class BlastRating(str, Enum):
    LOW    = "Low"
    MEDIUM = "Medium"
    HIGH   = "High"


class BlastRadius(BaseModel):
    finding_id: str
    finding_title: str
    direct_dependencies: list[str]    # node ids directly affected
    indirect_dependencies: list[str]  # transitively affected
    total_affected: int
    rating: BlastRating
    detail: str


# ==========================================================================
# v0.2.0 — PQC Migration Validation
# ==========================================================================

class PQCStatus(str, Enum):
    VALID              = "VALID"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    BLOCKED            = "BLOCKED"
    NOT_APPLICABLE     = "NOT_APPLICABLE"


class PQCValidationResult(BaseModel):
    finding_id: str
    finding_title: str
    current_algorithm: str
    purpose: str                      # "key-exchange" | "signature" | "symmetric" | "hash"
    recommended_pqc: Optional[str] = None
    status: PQCStatus
    reasons: list[str] = Field(default_factory=list)
    library_support: Optional[str] = None
    known_blockers: list[str] = Field(default_factory=list)
    is_heuristic: bool = True


# ==========================================================================
# v0.2.0 — Phased Remediation Plan
# ==========================================================================

class RemediationItem(BaseModel):
    finding_id: str
    finding_title: str
    priority: int              # 1 = highest
    effort_hours_estimate: float
    dependencies: list[str]   # other finding_ids this item depends on
    rationale: str


class RemediationPhase(BaseModel):
    phase_number: int
    name: str
    description: str
    timeframe: str             # e.g. "0-6 months"
    items: list[RemediationItem] = Field(default_factory=list)
    total_effort_hours: float = 0.0


class RemediationPlan(BaseModel):
    phases: list[RemediationPhase] = Field(default_factory=list)
    total_findings_addressed: int = 0
    total_effort_hours: float = 0.0
    generated_from_findings: bool = True


# ==========================================================================
# v0.2.0 — Migration Tickets
# ==========================================================================

class TicketPriority(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


class MigrationTicket(BaseModel):
    ticket_id: str
    title: str
    description: str
    affected_assets: list[str]         # file paths or asset names
    risk: str
    priority: TicketPriority
    recommended_migration: str
    dependencies: list[str] = Field(default_factory=list)  # other ticket_ids
    acceptance_criteria: list[str] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ==========================================================================
# v0.2.0 — CI/CD Policy
# ==========================================================================

class CICDAction(str, Enum):
    BLOCK = "BLOCK"
    WARN  = "WARN"
    ALLOW = "ALLOW"


class CICDPolicyResult(BaseModel):
    file_path: str
    finding_id: str
    finding_title: str
    severity: str
    action: CICDAction
    policy_rule: str


# ==========================================================================
# Crypto-Change Impact Simulator Models
# ==========================================================================

class SimulateRequest(BaseModel):
    finding_ids: list[str] = Field(default_factory=list)


class MetricDelta(BaseModel):
    original: float
    simulated: float
    delta: float


class RelatedFinding(BaseModel):
    id: str
    title: str
    severity: str
    category: str
    file_path: str
    relationship_reasons: list[str] = Field(default_factory=list)


class SimulateResponse(BaseModel):
    resolved_finding_ids: list[str]
    original_scores: ScoreBreakdown
    simulated_scores: ScoreBreakdown
    metric_deltas: dict[str, MetricDelta]
    grade_change: dict[str, str]
    summary_statement: str
    related_findings: dict[str, list[RelatedFinding]] = Field(default_factory=dict)
    disclaimer: str = (
        "Related by shared file/algorithm — not a verified dependency trace. "
        "A full blast-radius analysis would require call-graph analysis, which this scanner does not perform."
    )

class ScanSummary(BaseModel):
    scan_id: str
    target_name: str
    started_at: datetime
    completed_at: datetime
    files_scanned: int
    total_findings: int
    findings_by_severity: dict[str, int]
    findings_by_category: dict[str, int]
    findings_by_artifact_type: dict[str, int] = Field(default_factory=dict)
    findings_by_criticality: dict[str, int] = Field(default_factory=dict)
    mosca_at_risk_count: int = 0
    scores: ScoreBreakdown
    findings: list[Finding]
    # --- v0.2.0 extended analytics (all optional for backward compat) ---
    dependency_graph: Optional["CryptoDependencyGraph"] = None
    agility: Optional["AgilityScore"] = None
    blast_radii: Optional[list["BlastRadius"]] = None
    pqc_validations: Optional[list["PQCValidationResult"]] = None
    remediation_plan: Optional["RemediationPlan"] = None
    tickets: Optional[list["MigrationTicket"]] = None
    cicd_policy_results: Optional[list["CICDPolicyResult"]] = None



