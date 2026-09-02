import os
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.scanners.orchestrator import run_full_scan
from app.scoring.engine import compute_scores
from app.analysis.related_findings import find_related_findings
from app.models.schemas import SimulateRequest
from app.api.routes import simulate_fix, _SCANS, _summarize

demo_target = Path("backend/app/scanners/samples/demo_target").resolve()
print("Scanning demo target at:", demo_target)

findings, files_scanned = run_full_scan(str(demo_target))
scan = _summarize(findings, files_scanned, "demo_target")
_SCANS[scan.scan_id] = scan

print("\n--- ORIGINAL SCAN RESULTS ---")
print("Target:", scan.target_name)
print("Total Findings:", scan.total_findings)
print("Original Scores:", scan.scores.model_dump())
print("Original Grade:", scan.scores.grade)

# Pick critical/high findings to simulate resolving
critical_or_high = [f for f in scan.findings if f.severity.value in ("critical", "high")]
print(f"\nFound {len(critical_or_high)} Critical/High findings.")

selected_ids = [f.id for f in critical_or_high]

import asyncio
sim_req = SimulateRequest(finding_ids=selected_ids)
sim_res = asyncio.run(simulate_fix(scan.scan_id, sim_req))

print("\n--- SIMULATION RESULTS ---")
print("Resolved Findings Count:", len(sim_res.resolved_finding_ids))
print("Summary Statement:", sim_res.summary_statement)
print("Grade Change:", sim_res.grade_change)
print("Metric Deltas:")
for m, d in sim_res.metric_deltas.items():
    print(f"  {m}: original={d.original} -> simulated={d.simulated} (delta={d.delta})")

print("\n--- RELATED FINDINGS SAMPLE ---")
for fid, related in sim_res.related_findings.items():
    if related:
        f_obj = next(f for f in scan.findings if f.id == fid)
        print(f"Finding: '{f_obj.title}' in {f_obj.file_path}")
        for r in related:
            print(f"  -> Related: '{r.title}' ({r.severity}) | Reasons: {r.relationship_reasons}")

print("\nMandatory Disclaimer Present:", bool(sim_res.disclaimer))
print("VERIFICATION COMPLETED SUCCESSFULLY!")
