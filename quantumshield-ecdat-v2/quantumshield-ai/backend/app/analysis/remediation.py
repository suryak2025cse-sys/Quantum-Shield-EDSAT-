"""
Phased Remediation Plan Generator
=====================================
Dynamically generates a 3-phase migration plan from actual scan findings.

Phase 1 — Critical/Urgent (0-6 months):
  Findings that are: severity=CRITICAL, OR Mosca AT_RISK, OR PQC validation BLOCKED

Phase 2 — High-risk / Difficult (6-18 months):
  Findings that are: severity=HIGH, OR Mosca WATCH, OR PQC PARTIALLY_SUPPORTED,
  OR agility label DIFFICULT

Phase 3 — Remaining + Continuous Monitoring (18-36 months):
  All remaining quantum-vulnerable findings + monitoring recommendations

Each RemediationItem includes priority, effort estimate, and dependencies on
other item IDs (items with blocked validations must follow their prerequisites).

Effort estimation is deliberately rough — it is based only on agility factors
and finding counts since actual engineering velocity is not observable from
static analysis. Treat estimates as planning inputs, not commitments.
"""
from __future__ import annotations

from app.models.schemas import (
    AgilityLabel,
    AgilityScore,
    BlastRadius,
    BlastRating,
    Finding,
    MoscaRiskLevel,
    PQCStatus,
    PQCValidationResult,
    RemediationItem,
    RemediationPhase,
    RemediationPlan,
    Severity,
)

# Base effort hours per finding severity (heuristic)
EFFORT_BY_SEVERITY = {
    Severity.CRITICAL: 24.0,
    Severity.HIGH: 12.0,
    Severity.MEDIUM: 6.0,
    Severity.LOW: 2.0,
    Severity.INFO: 1.0,
}

AGILITY_MULTIPLIER = {
    AgilityLabel.EASY: 1.0,
    AgilityLabel.MODERATE: 1.5,
    AgilityLabel.DIFFICULT: 2.5,
}


def build_remediation_plan(
    findings: list[Finding],
    blast_radii: list[BlastRadius],
    validations: list[PQCValidationResult],
    agility: AgilityScore | None = None,
) -> RemediationPlan:
    """Build a 3-phase remediation plan from scan findings and analysis results."""
    if not findings:
        return RemediationPlan(phases=[], total_findings_addressed=0, total_effort_hours=0.0)

    multiplier = AGILITY_MULTIPLIER.get(agility.label if agility else AgilityLabel.MODERATE, 1.5)

    # Index validations and blast radii by finding_id
    val_by_fid = {v.finding_id: v for v in validations}
    blast_by_fid = {b.finding_id: b for b in blast_radii}

    phase1_ids: set[str] = set()
    phase2_ids: set[str] = set()
    phase3_ids: set[str] = set()

    for f in findings:
        val = val_by_fid.get(f.id)
        is_at_risk_mosca = bool(f.mosca and f.mosca.risk_level == MoscaRiskLevel.AT_RISK)
        is_blocked = val and val.status == PQCStatus.BLOCKED
        is_partially = val and val.status == PQCStatus.PARTIALLY_SUPPORTED
        is_watch = bool(f.mosca and f.mosca.risk_level == MoscaRiskLevel.WATCH)
        is_high_radius = blast_by_fid.get(f.id, None)
        is_high_blast = is_high_radius and is_high_radius.rating == BlastRating.HIGH

        if f.severity == Severity.CRITICAL or is_at_risk_mosca or is_blocked:
            phase1_ids.add(f.id)
        elif f.severity == Severity.HIGH or is_watch or is_partially or is_high_blast:
            phase2_ids.add(f.id)
        else:
            phase3_ids.add(f.id)

    # Ensure no overlap — phase1 takes priority
    phase2_ids -= phase1_ids
    phase3_ids -= phase1_ids | phase2_ids

    finding_map = {f.id: f for f in findings}

    def make_items(ids: set[str], priority_base: int) -> list[RemediationItem]:
        items = []
        for i, fid in enumerate(sorted(ids), start=1):
            f = finding_map.get(fid)
            if not f:
                continue
            base_effort = EFFORT_BY_SEVERITY.get(f.severity, 4.0) * multiplier
            # Increase effort for high blast radius
            br = blast_by_fid.get(fid)
            if br and br.rating == BlastRating.HIGH:
                base_effort *= 1.5

            val = val_by_fid.get(fid)
            deps = []
            if val and val.status == PQCStatus.BLOCKED:
                # Blocked items depend on their prerequisites (all phase1 items)
                deps = [fid2 for fid2 in phase1_ids if fid2 != fid][:3]

            items.append(RemediationItem(
                finding_id=fid,
                finding_title=f.title,
                priority=priority_base + i,
                effort_hours_estimate=round(base_effort, 1),
                dependencies=deps,
                rationale=_rationale(f, val, br),
            ))
        return items

    p1_items = make_items(phase1_ids, 0)
    p2_items = make_items(phase2_ids, len(p1_items))
    p3_items = make_items(phase3_ids, len(p1_items) + len(p2_items))

    monitoring_item = RemediationItem(
        finding_id="continuous-monitoring",
        finding_title="Establish continuous PQC monitoring",
        priority=len(p1_items) + len(p2_items) + len(p3_items) + 1,
        effort_hours_estimate=40.0,
        dependencies=[],
        rationale=(
            "Integrate QuantumShield into CI/CD pipelines to catch newly introduced "
            "quantum-vulnerable crypto. Configure alerting for certificate expiry of "
            "any PQC-migrated assets."
        ),
    )
    p3_items.append(monitoring_item)

    phases = [
        RemediationPhase(
            phase_number=1,
            name="Critical & Urgent",
            description=(
                "Address CRITICAL-severity findings, Mosca AT_RISK assets, and all "
                "BLOCKED PQC validations. These represent the highest immediate risk."
            ),
            timeframe="0-6 months",
            items=p1_items,
            total_effort_hours=round(sum(i.effort_hours_estimate for i in p1_items), 1),
        ),
        RemediationPhase(
            phase_number=2,
            name="High-Risk & Difficult Migrations",
            description=(
                "Migrate HIGH-severity findings, Mosca WATCH assets, PARTIALLY_SUPPORTED "
                "validations, and findings with high blast radius."
            ),
            timeframe="6-18 months",
            items=p2_items,
            total_effort_hours=round(sum(i.effort_hours_estimate for i in p2_items), 1),
        ),
        RemediationPhase(
            phase_number=3,
            name="Remaining Assets & Continuous Monitoring",
            description=(
                "Complete migration of remaining findings and establish ongoing monitoring "
                "and governance processes for crypto hygiene."
            ),
            timeframe="18-36 months",
            items=p3_items,
            total_effort_hours=round(sum(i.effort_hours_estimate for i in p3_items), 1),
        ),
    ]

    total_effort = round(sum(p.total_effort_hours for p in phases), 1)
    return RemediationPlan(
        phases=phases,
        total_findings_addressed=len(findings),
        total_effort_hours=total_effort,
        generated_from_findings=True,
    )


def _rationale(f: Finding, val: PQCValidationResult | None, br: BlastRadius | None) -> str:
    parts = []
    if f.mosca:
        parts.append(f"Mosca risk: {f.mosca.risk_level.value} (X+Y={f.mosca.x_plus_y}y vs Z={f.mosca.quantum_threat_horizon_years}y).")
    if val:
        parts.append(f"PQC validation: {val.status.value}.")
        if val.recommended_pqc:
            parts.append(f"Target: {val.recommended_pqc}.")
    if br:
        parts.append(f"Blast radius: {br.rating.value} ({br.total_affected} affected nodes).")
    return " ".join(parts) if parts else f"Severity: {f.severity.value}."
