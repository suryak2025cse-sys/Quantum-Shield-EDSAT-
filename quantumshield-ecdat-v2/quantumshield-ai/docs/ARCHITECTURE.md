# QuantumShield AI — Architecture

## 1. What's real in this build vs. what's scoped for post-hackathon

Being upfront about this distinction is itself a hackathon-judging signal — it's
what separates a startup pitch from a slideware demo.

| Component | Status in this build |
|---|---|
| Crypto & secrets scanner (regex/AST static analysis) | **Fully functional.** Runs against real code, tested against a sample vulnerable repo (see `backend/app/scanners/samples/demo_target`). |
| Certificate scanner (X.509) | **Fully functional.** Real ASN.1 parsing via the `cryptography` library — signature algorithm, key size, expiry, not regex-based. Tested against a real OpenSSL-generated SHA-1/RSA-1024 certificate. |
| Dependency/library scanner | **Fully functional** for requirements.txt/package.json/pom.xml/go.mod parsing and a bundled deprecated-library table. OSV.dev CVE lookup is real and wired up, but degrades gracefully (documented, not silent) when the network call fails or is blocked — treat CVE results as best-effort, not authoritative, until verified against a deployment with confirmed OSV.dev access. |
| HSM / cloud KMS detector | **Fully functional** pattern-based detection (AWS KMS, Azure Key Vault, GCP KMS, PKCS#11, named HSM vendors). Cannot inspect the HSM/KMS's actual configuration — that lives outside the codebase by definition. |
| Binary scanner | **Fully functional strings-based scan** (library version banners, crypto symbol names) — tested against a synthetic binary with embedded OpenSSL/RSA/SHA-1 strings. This is a legitimate first-pass technique, explicitly not full disassembly/control-flow analysis — see `binary_scanner.py` docstring for the scope boundary. |
| Container image scanner | **Fully functional** real `docker save` tar/layer extraction and flattening, tested against a manually-constructed multi-layer image archive (no Docker daemon was available in the build environment, so a real `docker save` output couldn't be produced directly — but the tar/manifest format consumed is Docker's actual documented format). Does not query in-image OS package managers (dpkg/rpm) for a full installed-package inventory — flagged as a known limitation. |
| Business criticality classification | **Fully functional heuristic** (path-keyword based) with a documented override mechanism (upload a JSON path→criticality map). Heuristics are a starting point, not a substitute for an organization's real asset register. |
| Exposure (internal/external) classification | **Fully functional signal-based detection** from Dockerfile `EXPOSE` and Kubernetes Service/Ingress manifests — reports `unknown` rather than guessing when no such manifest is present, since static code can't see real network topology. |
| Mosca's algorithm | **Fully functional** computed X+Y vs. Z assessment (see `app/analysis/mosca.py`), not a placeholder boolean. Default X/Y assumptions are documented, cited heuristics, fully overridable via `MoscaConfig`. |
| CycloneDX 1.6 CBOM export | **Fully functional**, targets the real CycloneDX 1.6 `cryptographic-asset` schema (verified against the published spec before implementation). Not yet run through the official CycloneDX JSON schema validator — treat as a faithful implementation, not a certified-conformant one, until that step is added. |
| Scoring engine (Security / Quantum Readiness / Compliance / Criticality) | **Fully functional.** Deterministic, unit-testable math — see `app/scoring/engine.py`. Now also weighs certificate, library, and HSM findings, not just the original crypto/secrets categories. |
| AI Advisor (explanations, roadmap, copilot chat) | **Fully functional**, calls the real Anthropic API. Requires `ANTHROPIC_API_KEY`. |
| REST API (FastAPI) | **Fully functional**, runnable standalone (`uvicorn app.main:app`). Verified via `TestClient` round-trip including `.zip` upload and CBOM export. |
| Dashboard UI | **Fully functional** React app: Overview, Findings, Asset Inventory (CBOM view), Quantum Readiness, Reports, Copilot — all wired to live API responses, no mock data. |
| MongoDB persistence, Redis/Celery async scanning | **Scaffolded**, config + docker-compose wiring included; scan storage is in-memory in this build to keep it runnable without infra. |
| GitHub/CI integration | **Architected, not implemented.** Same extensible pattern as every other scanner — see §4.

## 2. High-level architecture

```
                    ┌─────────────────────────┐
                    │   React Dashboard (SPA)  │
                    │  Vite + TS + Tailwind    │
                    └────────────┬─────────────┘
                                 │ REST (JSON)
                    ┌────────────▼─────────────┐
                    │      FastAPI Gateway      │
                    │  /api/v1/scans, /copilot  │
                    └───┬────────┬──────────┬───┘
                        │        │          │
          ┌─────────────▼──┐ ┌───▼─────┐ ┌──▼──────────────┐
          │ Scanner Engine  │ │ Scoring │ │  AI Advisor      │
          │ (crypto/secret/ │ │ Engine  │ │  (Claude API)    │
          │  dependency/cfg)│ │         │ │                  │
          └────────┬────────┘ └─────────┘ └──────────────────┘
                   │
        ┌──────────▼──────────┐
        │  Celery + Redis      │   ← async scan jobs for large repos
        │  (queued scan tasks) │
        └──────────┬───────────┘
                   │
        ┌──────────▼──────────┐
        │  MongoDB (Motor)      │   ← scan history, findings, org/user data
        └────────────────────────┘
```

## 3. Why this stack

- **FastAPI over Django/Flask**: native async support matters because scans
  fan out to many I/O-bound calls (file reads, future CVE lookups, LLM calls).
  Pydantic models double as the API contract and the internal data model
  (`app/models/schemas.py`), so there's one source of truth, not three.
- **MongoDB over Postgres**: findings are heterogeneous, semi-structured
  documents (a secret finding and a certificate finding share a base shape
  but not all fields) — a document store avoids a findings table with 40
  mostly-null columns or a brittle EAV pattern.
- **Celery + Redis for scan execution**: scanning a large monorepo can take
  minutes; it must not block the request thread or the AI-explanation calls
  that depend on scan completion.
- **React + Recharts + Tailwind**: fast iteration for a dashboard-heavy
  product; Recharts covers every chart type in this spec (radial gauges,
  donuts, area trends) without a heavier charting library.

## 4. Scanner extensibility pattern

Every scanner (`crypto_scanner.py` is the reference implementation) follows
the same contract: **input a target, output `list[Finding]`**. Adding a new
scanner (e.g. dependency CVE lookup via OSV.dev) means:

1. Define new `Category` / rules if needed in `models/schemas.py`.
2. Implement `scan_x(target) -> list[Finding]` following the existing shape.
3. Register it in `api/routes.py`'s scan orchestration.

No changes are needed to the scoring engine, AI advisor, or report generator
— they all operate on `Finding` objects generically. This is the core
architectural bet that keeps 18 "modules" from becoming 18 bespoke pipelines.

## 5. On quantum computing in this product (important design decision)

A real "quantum readiness" product does **not** run cryptographic attacks on
a quantum simulator against a customer's RSA keys — that would take longer
than the age of the universe on today's hardware for any real key size, and
provides zero product value even if it didn't. What real CBOM (Cryptographic
Bill of Materials) and quantum-readiness tools do — including tooling from
the Linux Foundation's PQCA and vendor tools from IBM/Google/Microsoft — is
exactly what this scanner does: **statically identify which algorithms are
in use**, classify them against NIST's post-quantum migration guidance
(FIPS 203/204/205, CNSA 2.0, NSM-10), and prioritize by "harvest now, decrypt
later" exposure. Qiskit's actual role in this space is for the *cryptography
research* side (estimating real-world qubit/gate counts to break RSA-2048,
tracking hardware progress) — not something a scanning SaaS product runs
per-customer. We reference this honestly in the pitch rather than bolting on
a Qiskit import that would be decorative.

## 6. Security of the platform itself

- Secrets found during scans are **redacted before storage/display**
  (`crypto_scanner.py::scan_file` replaces the matched secret value in the
  stored snippet) — a security product that logs plaintext customer secrets
  is a liability, not a feature.
- API keys (Anthropic, cloud) are read from environment/secret manager, never
  committed — same standard we hold customer code to.
- Multi-tenant isolation: scan data is scoped by org/user ID (schema supports
  this; enforcement middleware is a pre-launch task).
