# QuantumShield AI — Business Case

## Why now

NIST finalized its first three post-quantum cryptography standards (ML-KEM
FIPS 203, ML-DSA FIPS 204, SLH-DSA FIPS 205) in August 2024. The US NSM-10
memo directs federal systems toward PQC migration on a defined timeline, and
CNSA 2.0 sets deadlines through 2033 for national security systems. Most
organizations have no inventory of where RSA/ECC is actually used across
their codebase, dependencies, and certificates — you cannot migrate what you
haven't found. That inventory gap is the wedge.

## Target segments (ranked by urgency)

1. **Regulated finance & payments** — long-lived transaction records, PCI-DSS
   overlap, "harvest now decrypt later" directly threatens customer PII.
2. **Government & defense contractors** — CNSA 2.0 compliance is becoming a
   contract requirement, not optional.
3. **Healthcare** — decades-long confidentiality requirements on patient data.
4. **Cloud/SaaS platforms** — need to prove crypto-agility to enterprise
   customers doing vendor security review.

## Competitive landscape

| Category | Examples | Gap QuantumShield fills |
|---|---|---|
| Classical SAST/secret scanners | Snyk, GitGuardian, Semgrep | No quantum-readiness dimension at all |
| PQC-specific tooling | IBM Quantum Safe, PQShield, SandboxAQ | Enterprise-priced, consulting-heavy, not self-serve developer-first SaaS |
| General cloud security posture | Wiz, Orca | Broad but shallow on cryptographic inventory specifically |

**Positioning**: the only platform that unifies today's-attacker security
scanning with tomorrow's-quantum-attacker readiness in one score, one
dashboard, one migration plan — instead of making security teams stitch
together a classical scanner and a separate PQC consulting engagement.

## Revenue model

- **Team** — $499/mo: up to 10 repos, weekly scans, email reports.
- **Business** — $2,499/mo: unlimited repos, CI/CD gating, Slack/Jira
  integration, compliance reports (SOC2/PCI mapping).
- **Enterprise** — custom (typically $50K–$250K/yr): SSO/SAML, on-prem/VPC
  deployment, dedicated migration advisory, custom SLAs.
- **API/usage add-on**: per-scan pricing for CI pipeline integrations beyond
  plan limits.
- **Professional services**: fixed-fee migration roadmap workshops for
  Enterprise accounts — high-margin, and it's the natural upsell once a scan
  surfaces the scope of an org's crypto debt.

## Illustrative cost structure (early stage, illustrative only)

- LLM inference (Claude API calls for explanations/roadmap/copilot): scales
  with scan volume; mitigated by the rule-level explanation cache in
  `app/ai/advisor.py` (same rule firing 40× in a repo -> 1 LLM call, not 40).
  Order-of-magnitude estimate: pennies per scan at moderate finding counts.
- Compute (scanning workers, API hosting): standard containerized workload,
  scales horizontally with Celery workers.
- These are estimates for planning purposes, not audited figures — real unit
  economics need a pilot cohort's actual usage data before they're claimed
  with confidence.

## Go-to-market

- **Bottom-up**: free/open scan of a single public repo (viral loop — "what's
  your Quantum Readiness Score?" is a shareable, competitive artifact, similar
  to how Snyk and SSL Labs drove adoption with free scan-and-share tools).
- **Top-down**: compliance deadlines (CNSA 2.0, emerging EU/UK guidance) give
  security leaders budget justification without QuantumShield having to
  create the urgency itself.

## Risks and honest counterpoints

- **Timeline risk**: cryptographically relevant quantum computers may be
  5–20+ years out — some buyers will deprioritize PQC migration. Mitigation:
  the platform's classical security scanning delivers standalone value today,
  independent of the quantum timeline.
- **Incumbent expansion**: Snyk/Wiz could bolt on a crypto-inventory feature.
  Mitigation: speed to a genuinely unified score/roadmap product, and
  depth on the PQC-specific migration workflow they're unlikely to prioritize
  early.

## Roadmap (post-hackathon)

- **0–3 months**: dependency CVE scanner (OSV.dev integration), certificate
  chain scanner (`cryptography.x509`), persistent storage (Mongo), auth.
- **3–6 months**: GitHub App (PR-diff scanning, inline PR comments), CI/CD
  plugin (GitHub Actions, GitLab CI), Slack/Jira notifications.
- **6–12 months**: SBOM/CBOM export (CycloneDX format), SOC2/PCI compliance
  report mapping, multi-repo org-wide dashboards, RBAC/SSO for Enterprise.

## Judge Q&A — likely questions and honest answers

**"Is this just a regex scanner with an LLM wrapper?"**
The detection layer is intentionally simple and explainable — that's a
feature, not a limitation. Real CBOM/PQC-inventory tools in production today
work the same way (static pattern/AST matching against known primitive
names), because crypto usage shows up as specific, named API calls, not
subtle behavioral patterns that need ML. The AI's job is explanation,
prioritization, and roadmap synthesis — the parts that genuinely benefit
from an LLM — not detection, where a probabilistic model would be worse than
deterministic rules.

**"What happens when quantum computers never arrive at scale?"**
The classical security scanning (secrets, weak TLS, JWT misconfig, MD5/SHA1)
stands alone as a sellable product today. Quantum readiness is the
differentiator and timing wedge, not the sole value prop.

**"How do you avoid false positives at scale?"**
Rule-level review, allowlisting/suppression per finding (schema supports a
suppressed/acknowledged state — a near-term addition), and the AI advisor
can down-rank contextually irrelevant matches (e.g. RSA referenced in a test
fixture vs. production key generation) once fed richer file-path context.
