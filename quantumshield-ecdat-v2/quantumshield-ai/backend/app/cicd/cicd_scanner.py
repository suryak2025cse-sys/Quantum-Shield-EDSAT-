"""
CI/CD Security Gate Scanner
==============================
Standalone module (also importable) that scans a directory for newly
introduced cryptographic risks and enforces configurable policies.

Design constraints:
  - NEVER executes customer application code
  - Works entirely from static source analysis (uses crypto_scanner.py)
  - Compares against an optional baseline JSON to detect NEW regressions only
  - Exits with code 1 if any BLOCK policy is triggered (suitable for CI gates)
  - Produces machine-readable JSON reports

CLI usage:
    python -m app.cicd.cicd_scanner \
        --dir /path/to/changed/files \
        --policy app/cicd/default_policy.json \
        --baseline baseline.json \
        --output report.json

Policy JSON schema:
    {
        "rules": [
            {"severity": "critical", "action": "BLOCK"},
            {"severity": "high",     "action": "WARN"},
            {"category": "secret",   "action": "BLOCK"},
            {"finding_id": "QC-RSA-001", "action": "BLOCK"}
        ],
        "exceptions": [
            {"file_path": "tests/", "reason": "Test fixtures"}
        ]
    }
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from app.models.schemas import CICDAction, CICDPolicyResult, Finding
from app.scanners.crypto_scanner import scan_directory

# Default policy applied when no config file is provided
DEFAULT_POLICY: dict[str, Any] = {
    "rules": [
        {"severity": "critical", "action": "BLOCK"},
        {"severity": "high", "action": "WARN"},
        {"category": "secret", "action": "BLOCK"},
        {"category": "quantum_vulnerable_crypto", "action": "WARN"},
    ],
    "exceptions": [],
}


def load_policy(policy_path: str | None) -> dict[str, Any]:
    if not policy_path:
        return DEFAULT_POLICY
    try:
        with open(policy_path, "r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[WARNING] Could not load policy file {policy_path}: {e}. Using default policy.", file=sys.stderr)
        return DEFAULT_POLICY


def load_baseline(baseline_path: str | None) -> set[str]:
    """Load a set of finding 'fingerprints' from a previous scan baseline.
    Fingerprint = matched_pattern + file_path + category (stable across re-scans).
    """
    if not baseline_path:
        return set()
    try:
        with open(baseline_path, "r") as f:
            data = json.load(f)
        return set(data.get("fingerprints", []))
    except (OSError, json.JSONDecodeError) as e:
        print(f"[WARNING] Could not load baseline {baseline_path}: {e}. Treating all findings as new.", file=sys.stderr)
        return set()


def fingerprint(finding: Finding) -> str:
    return f"{finding.matched_pattern or 'unknown'}::{finding.file_path}::{finding.category.value}"


def _is_exception(finding: Finding, exceptions: list[dict]) -> bool:
    for exc in exceptions:
        path_prefix = exc.get("file_path", "")
        if path_prefix and finding.file_path.startswith(path_prefix):
            return True
    return False


def apply_policy(
    finding: Finding,
    policy: dict[str, Any],
) -> tuple[CICDAction, str]:
    """Return the (action, rule_description) for a finding."""
    exceptions = policy.get("exceptions", [])
    if _is_exception(finding, exceptions):
        return CICDAction.ALLOW, "exception"

    for rule in policy.get("rules", []):
        action_str = rule.get("action", "ALLOW").upper()
        action = CICDAction(action_str) if action_str in ("BLOCK", "WARN", "ALLOW") else CICDAction.ALLOW

        # Match on severity
        if "severity" in rule and finding.severity.value == rule["severity"]:
            return action, f"severity={rule['severity']}"
        # Match on category
        if "category" in rule and finding.category.value == rule["category"]:
            return action, f"category={rule['category']}"
        # Match on specific finding / rule ID
        if "finding_id" in rule and finding.matched_pattern == rule["finding_id"]:
            return action, f"finding_id={rule['finding_id']}"

    return CICDAction.ALLOW, "no-matching-rule"


def run_cicd_scan(
    target_dir: str,
    policy: dict[str, Any] | None = None,
    baseline_fingerprints: set[str] | None = None,
) -> tuple[list[CICDPolicyResult], bool]:
    """
    Scan target_dir, apply policy, and return (results, should_fail).

    Returns:
        results          — list of CICDPolicyResult (one per new finding)
        should_fail      — True if any result has action=BLOCK
    """
    if policy is None:
        policy = DEFAULT_POLICY
    if baseline_fingerprints is None:
        baseline_fingerprints = set()

    findings, _ = scan_directory(target_dir)

    # Filter to only NEW findings not in baseline
    new_findings = [f for f in findings if fingerprint(f) not in baseline_fingerprints]

    results: list[CICDPolicyResult] = []
    should_fail = False

    for f in new_findings:
        action, rule_desc = apply_policy(f, policy)
        if action == CICDAction.BLOCK:
            should_fail = True
            msg = f"BLOCKED by policy rule '{rule_desc}': {f.title} in {f.file_path}"
        elif action == CICDAction.WARN:
            msg = f"WARNING by policy rule '{rule_desc}': {f.title} in {f.file_path}"
        else:
            msg = f"ALLOWED by policy rule '{rule_desc}': {f.title} in {f.file_path}"

        results.append(CICDPolicyResult(
            file_path=f.file_path,
            finding_id=f.id,
            finding_title=f.title,
            severity=f.severity.value,
            action=action,
            policy_rule=rule_desc,
            message=msg,
        ))

    return results, should_fail


def generate_report(results: list[CICDPolicyResult], target_dir: str) -> dict:
    """Generate a machine-readable JSON report."""
    blocks = [r for r in results if r.action == CICDAction.BLOCK]
    warns = [r for r in results if r.action == CICDAction.WARN]
    allows = [r for r in results if r.action == CICDAction.ALLOW]

    return {
        "quantumshield_cicd_report": {
            "target": target_dir,
            "summary": {
                "total_new_findings": len(results),
                "blocked": len(blocks),
                "warned": len(warns),
                "allowed": len(allows),
                "gate_passed": len(blocks) == 0,
            },
            "results": [
                {
                    "file": r.file_path,
                    "finding_id": r.finding_id,
                    "title": r.finding_title,
                    "severity": r.severity,
                    "action": r.action.value,
                    "policy_rule": r.policy_rule,
                    "message": r.message,
                }
                for r in results
            ],
        }
    }


def generate_sarif_report(results: list[CICDPolicyResult], target_dir: str) -> dict:
    """Generate official OASIS SARIF 2.1.0 report for GitHub Code Scanning integration."""
    rules_map: dict[str, dict] = {}
    sarif_results = []

    for r in results:
        rule_id = r.policy_rule or "QUANTUMSHIELD-RULE"
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": r.finding_title,
                "shortDescription": {"text": r.finding_title},
                "fullDescription": {"text": r.message},
                "defaultConfiguration": {
                    "level": "error" if r.action == CICDAction.BLOCK else ("warning" if r.action == CICDAction.WARN else "note")
                },
            }

        sarif_results.append({
            "ruleId": rule_id,
            "level": "error" if r.action == CICDAction.BLOCK else ("warning" if r.action == CICDAction.WARN else "note"),
            "message": {"text": r.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": r.file_path.replace("\\", "/")},
                        "region": {"startLine": 1},
                    }
                }
            ],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "QuantumShield AI CI/CD Gate",
                        "version": "0.2.0",
                        "informationUri": "https://github.com/quantumshield-ai",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def save_baseline(findings: list[Finding], output_path: str) -> None:
    """Save current scan fingerprints as a new baseline for future comparisons."""
    fps = [fingerprint(f) for f in findings]
    with open(output_path, "w") as out:
        json.dump({"fingerprints": fps, "count": len(fps)}, out, indent=2)
    print(f"[INFO] Baseline saved to {output_path} ({len(fps)} fingerprints)")


# ---------------------------------------------------------------------------
# CLI entry point (python -m app.cicd.cicd_scanner)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="quantumshield-cicd",
        description="QuantumShield AI CI/CD Security Gate Scanner",
    )
    parser.add_argument("--dir", required=True, help="Directory (or changed-files dir) to scan")
    parser.add_argument("--policy", default=None, help="Path to policy JSON file")
    parser.add_argument("--baseline", default=None, help="Path to baseline fingerprints JSON")
    parser.add_argument("--format", choices=["json", "sarif"], default="json", help="Output format: json (default) or sarif")
    parser.add_argument("--output", default=None, help="Write report to this file")
    parser.add_argument("--save-baseline", default=None, dest="save_baseline_path",
                        help="Save current scan as new baseline to this path")
    args = parser.parse_args()

    pol = load_policy(args.policy)
    base = load_baseline(args.baseline)
    results, fail = run_cicd_scan(args.dir, pol, base)

    if args.format == "sarif":
        report = generate_sarif_report(results, args.dir)
    else:
        report = generate_report(results, args.dir)

    report_str = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(report_str)
        print(f"[INFO] Report written to {args.output}")
    else:
        print(report_str)

    if args.save_baseline_path:
        findings_all, _ = scan_directory(args.dir)
        save_baseline(findings_all, args.save_baseline_path)

    if fail:
        print("\n[FAIL] One or more BLOCK policy rules were triggered. Pipeline failed.", file=sys.stderr)
        sys.exit(1)
    else:
        print("\n[PASS] No BLOCK policy rules triggered. Pipeline passed.")
        sys.exit(0)
