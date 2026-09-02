"""
Migration Ticket Generator
============================
Produces GitHub/Jira-style migration tickets from scan findings.

One ticket is generated per CRITICAL or HIGH finding that warrants
a migration task. Tickets are pure data — no live GitHub/Jira API calls
are made. The caller can export them as JSON or Markdown for use with any
issue tracker.

Ticket structure (matches GitHub Issues / Jira tickets):
  - title
  - description (what was found and why it matters)
  - affected_assets (file paths)
  - risk (plain-language string)
  - priority (critical | high | medium | low)
  - recommended_migration (from NIST PQC recommendation or remediation text)
  - dependencies (other ticket IDs this ticket depends on)
  - acceptance_criteria (what "done" looks like)
  - labels (for filtering in issue trackers)
  - finding_ids (for traceability back to scan)
"""
from __future__ import annotations

import uuid
from datetime import datetime

from app.models.schemas import (
    BlastRadius,
    BlastRating,
    Finding,
    MigrationTicket,
    MoscaRiskLevel,
    PQCStatus,
    PQCValidationResult,
    RemediationPlan,
    Severity,
    TicketPriority,
)

_SEVERITY_TO_TICKET_PRIORITY = {
    Severity.CRITICAL: TicketPriority.CRITICAL,
    Severity.HIGH: TicketPriority.HIGH,
    Severity.MEDIUM: TicketPriority.MEDIUM,
    Severity.LOW: TicketPriority.LOW,
    Severity.INFO: TicketPriority.LOW,
}

_TICKET_LABELS = {
    "quantum_vulnerable_crypto": ["quantum-security", "pqc-migration", "needs-upgrade"],
    "certificate_issue": ["certificate", "quantum-security", "pqc-migration"],
    "classical_crypto_weakness": ["crypto-weakness", "needs-upgrade"],
    "secret": ["secret-exposure", "critical-security"],
    "auth_weakness": ["auth", "needs-upgrade"],
    "dependency_cve": ["dependency", "cve", "needs-upgrade"],
    "hsm_cloud_kms": ["kms", "hardware", "vendor-coordination"],
    "binary_artifact": ["binary", "needs-source"],
}


def generate_tickets(
    findings: list[Finding],
    blast_radii: list[BlastRadius],
    validations: list[PQCValidationResult],
    remediation_plan: RemediationPlan | None = None,
) -> list[MigrationTicket]:
    """Generate migration tickets for CRITICAL and HIGH findings."""
    br_by_fid = {b.finding_id: b for b in blast_radii}
    val_by_fid = {v.finding_id: v for v in validations}

    # Only generate tickets for critical and high severity
    ticketable = [
        f for f in findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]

    # Map finding_id → ticket_id for dependency resolution
    finding_ticket_ids: dict[str, str] = {}
    tickets: list[MigrationTicket] = []

    for f in ticketable:
        ticket_id = f"QS-{uuid.uuid4().hex[:8].upper()}"
        finding_ticket_ids[f.id] = ticket_id

    for f in ticketable:
        ticket_id = finding_ticket_ids[f.id]
        br = br_by_fid.get(f.id)
        val = val_by_fid.get(f.id)

        priority = _SEVERITY_TO_TICKET_PRIORITY.get(f.severity, TicketPriority.MEDIUM)
        labels = list(_TICKET_LABELS.get(f.category.value, ["security", "needs-upgrade"]))
        if br and br.rating == BlastRating.HIGH:
            labels.append("high-blast-radius")
        if f.mosca and f.mosca.risk_level == MoscaRiskLevel.AT_RISK:
            labels.append("mosca-at-risk")
        if val and val.status == PQCStatus.BLOCKED:
            labels.append("migration-blocked")

        # Dependencies: tickets for phase1 items this one depends on
        dep_ticket_ids: list[str] = []
        if remediation_plan:
            for phase in remediation_plan.phases:
                for item in phase.items:
                    for dep_fid in item.dependencies:
                        dep_tid = finding_ticket_ids.get(dep_fid)
                        if dep_tid and dep_tid != ticket_id:
                            dep_ticket_ids.append(dep_tid)

        recommended = (
            val.recommended_pqc if val and val.recommended_pqc
            else (f.nist_pqc_recommendation or f.remediation or "See remediation notes.")
        )

        description = _build_description(f, val, br)
        acceptance = _build_acceptance_criteria(f, val)
        risk = _build_risk(f, br)

        tickets.append(MigrationTicket(
            ticket_id=ticket_id,
            title=f"[{f.severity.value.upper()}] {f.title}",
            description=description,
            affected_assets=[f.file_path] + (
                [f"{f.file_path}:{f.line_number}"] if f.line_number else []
            ),
            risk=risk,
            priority=priority,
            recommended_migration=recommended,
            dependencies=list(set(dep_ticket_ids)),
            acceptance_criteria=acceptance,
            labels=sorted(set(labels)),
            finding_ids=[f.id],
            created_at=datetime.utcnow(),
        ))

    return tickets


def ticket_to_markdown(ticket: MigrationTicket) -> str:
    """Serialize a ticket to GitHub-compatible Markdown."""
    lines = [
        f"# {ticket.ticket_id}: {ticket.title}",
        "",
        f"**Priority:** {ticket.priority.value.upper()}  ",
        f"**Labels:** {', '.join(ticket.labels)}  ",
        f"**Created:** {ticket.created_at.strftime('%Y-%m-%d')}",
        "",
        "## Description",
        ticket.description,
        "",
        "## Affected Assets",
    ]
    for asset in ticket.affected_assets:
        lines.append(f"- `{asset}`")
    lines += [
        "",
        "## Risk",
        ticket.risk,
        "",
        "## Recommended Migration",
        ticket.recommended_migration,
        "",
    ]
    if ticket.dependencies:
        lines.append("## Dependencies")
        for dep in ticket.dependencies:
            lines.append(f"- {dep}")
        lines.append("")
    lines.append("## Acceptance Criteria")
    for ac in ticket.acceptance_criteria:
        lines.append(f"- [ ] {ac}")
    lines += [
        "",
        "---",
        f"*Generated by QuantumShield AI · Finding IDs: {', '.join(ticket.finding_ids)}*",
    ]
    return "\n".join(lines)


def ticket_to_dict(ticket: MigrationTicket) -> dict:
    """Serialize a ticket to a plain dict for JSON export / API integration hooks."""
    return {
        "ticket_id": ticket.ticket_id,
        "title": ticket.title,
        "description": ticket.description,
        "affected_assets": ticket.affected_assets,
        "risk": ticket.risk,
        "priority": ticket.priority.value,
        "recommended_migration": ticket.recommended_migration,
        "dependencies": ticket.dependencies,
        "acceptance_criteria": ticket.acceptance_criteria,
        "labels": ticket.labels,
        "finding_ids": ticket.finding_ids,
        "created_at": ticket.created_at.isoformat(),
        # API integration hooks — fill in with your org's values
        "_integration_hooks": {
            "github": {
                "endpoint": "POST https://api.github.com/repos/{owner}/{repo}/issues",
                "body_template": {
                    "title": ticket.title,
                    "body": "Replace with ticket_to_markdown() output",
                    "labels": ticket.labels,
                },
            },
            "jira": {
                "endpoint": "POST https://{domain}.atlassian.net/rest/api/3/issue",
                "body_template": {
                    "fields": {
                        "summary": ticket.title,
                        "description": ticket.description,
                        "priority": {"name": ticket.priority.value.capitalize()},
                        "labels": ticket.labels,
                    }
                },
            },
        },
    }


def _build_description(f: Finding, val: PQCValidationResult | None, br: BlastRadius | None) -> str:
    parts = [f.description]
    if f.mosca:
        parts.append(
            f"\n\n**Mosca Assessment:** X+Y = {f.mosca.x_plus_y}y vs. Z = {f.mosca.quantum_threat_horizon_years}y "
            f"→ **{f.mosca.risk_level.value.replace('_', ' ').title()}** — {f.mosca.rationale}"
        )
    if val and val.reasons:
        parts.append(f"\n\n**PQC Validation ({val.status.value}):**")
        for r in val.reasons:
            parts.append(f"\n- {r}")
        if val.known_blockers:
            parts.append(f"\n\n**Known Blockers:**")
            for b in val.known_blockers:
                parts.append(f"\n- {b}")
    if br:
        parts.append(
            f"\n\n**Blast Radius:** {br.rating.value} — {br.detail}"
        )
    return "".join(parts)


def _build_acceptance_criteria(f: Finding, val: PQCValidationResult | None) -> list[str]:
    criteria = [
        f"The cryptographic usage at `{f.file_path}`{(':' + str(f.line_number)) if f.line_number else ''} has been replaced.",
        "All tests pass after migration.",
        "A security code review has been completed and signed off.",
    ]
    if val and val.recommended_pqc:
        criteria.append(f"Replacement uses {val.recommended_pqc} as the target algorithm.")
    if f.cwe_id:
        criteria.append(f"CWE-{f.cwe_id.replace('CWE-', '')} no longer applicable to this code path.")
    criteria.append("QuantumShield re-scan shows this finding resolved.")
    return criteria


def _build_risk(f: Finding, br: BlastRadius | None) -> str:
    risk = f"Severity: **{f.severity.value.upper()}**. {f.description[:200]}..."
    if br:
        risk += f" Migration blast radius: **{br.rating.value}** ({br.total_affected} dependent nodes)."
    return risk
