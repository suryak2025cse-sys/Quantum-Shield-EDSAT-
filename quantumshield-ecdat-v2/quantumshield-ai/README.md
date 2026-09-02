# QuantumShield AI (v0.2.0)
### Enterprise Cryptographic Bill of Materials (CBOM) & Quantum-Readiness Analytics Platform

QuantumShield AI discovers cryptographic artefacts across source repositories, dependencies, containers, binaries, certificates, and protocols. It performs quantum-risk assessment, applies **Mosca’s Theorem ($X+Y>Z$)**, evaluates **NIST PQC migration paths (FIPS 203/204/205)**, and exports standardized **CycloneDX 1.6 CBOM** and **SARIF 2.1.0** reports.

---

## Key Capabilities

1. **Comprehensive Discovery Engine (14 Ecosystems & Layers)**
   - **Source Code & Manifests**: Python (requirements.txt, pyproject.toml, poetry.lock, Pipfile.lock), JavaScript/TypeScript (package.json, package-lock, yarn.lock, pnpm-lock), Java (pom.xml, build.gradle), Go (go.mod, go.sum), Rust (Cargo.toml, Cargo.lock).
   - **X.509 Certificates**: Deep PEM/DER parsing (SANs, validity windows, signature algorithms, serials, self-signed detection, CA constraints).
   - **Protocols & Channels**: TLS 1.0-1.3, SSH hostkeys/kex, IPsec IKEv1/IKEv2, mTLS client verification, QUIC, and JWT/JOSE alg:none checks.
   - **Container Images**: Docker/OCI tar multi-layer extraction, `.wh.*` whiteout processing, and OS package database inspection (Debian `dpkg`, Alpine `apk`).
   - **Binaries**: ELF, PE, and Mach-O header/architecture detection and embedded cryptographic symbols.

2. **Normalized CBOM & Asset Inventory**
   - Deduplicates finding instances into canonical cryptographic assets with stable SHA-256 fingerprints, locations, occurrences, and lifecycle metadata.

3. **Formal Quantum Risk Assessment (Mosca's Inequality)**
   - Calculates $X$ (Data Security Lifetime) + $Y$ (Migration Duration) vs. $Z$ (CRQC Threat Horizon).
   - Interactive multi-horizon sensitivity matrix ($Z = 5, 10, 15, 20\text{ years}$).

4. **NIST PQC Migration Engine & Effort Modeling**
   - Direct mappings to NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA).
   - Recommends hybrid transitions (e.g. X25519 + ML-KEM-768).
   - Quantifies estimated engineering effort (hours), network latency overhead (+ms), and cost profile ($ to $$$$).

5. **Standards-Compliant Exports**
   - **CycloneDX 1.6 CBOM**: Compliant JSON schema with component dependency graphs and cryptographic properties.
   - **OASIS SARIF 2.1.0**: Automated GitHub Code Scanning integration.

6. **Deterministic Offline AI Copilot & Remediation**
   - Operates fully offline with rule-based expert intelligence; automatically switches to Anthropic Claude when API key is provided.
   - Generates actionable Jira/GitHub remediation tickets with code snippets.

---

## Quick Start

### 1. Standalone CLI Scan (No server needed)
```bash
# Windows PowerShell
py -3.12 -m app.scanners.orchestrator app/scanners/samples/demo_target --offline --output cbom.json

# Linux / macOS
python3 -m app.scanners.orchestrator app/scanners/samples/demo_target --offline --output cbom.json
```

### 2. Run Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
# OpenAPI Docs: http://localhost:8000/docs
# Health Check: http://localhost:8000/health
```

### 3. Run Frontend
```bash
cd frontend
npm install
npm run dev
# Dashboard: http://localhost:5173
```

### 4. Run CI/CD Gate Scanner
```bash
python -m app.cicd.cicd_scanner --dir . --policy backend/app/cicd/default_policy.json --format sarif --output results.sarif
```

### 5. Run Test Suite
```bash
cd backend
pytest tests -v
```

---

## Architecture Overview

```
quantumshield-ai/
+-- backend/
¦   +-- app/
¦   ¦   +-- main.py                  # FastAPI Application & health endpoints
¦   ¦   +-- worker.py                # Celery background worker
¦   ¦   +-- api/routes.py            # REST endpoints, safe upload, git clone
¦   ¦   +-- cbom/cyclonedx_export.py # CycloneDX 1.6 JSON CBOM generator
¦   ¦   +-- cicd/cicd_scanner.py     # CI/CD Gate scanner & SARIF 2.1.0 exporter
¦   ¦   +-- analysis/
¦   ¦   ¦   +-- asset_inventory.py   # Normalized CBOM deduplication
¦   ¦   ¦   +-- mosca.py             # Mosca theorem & sensitivity matrix
¦   ¦   ¦   +-- pqc_validator.py     # NIST PQC migration validator & metrics
¦   ¦   ¦   +-- agility.py           # Cryptographic agility scoring
¦   ¦   ¦   +-- blast_radius.py      # Dependency blast radius graph
¦   ¦   ¦   +-- classification.py    # Business criticality & metadata profiles
¦   ¦   ¦   +-- remediation.py       # Phased remediation planner
¦   ¦   ¦   +-- tickets.py           # Jira/GitHub ticket generator
¦   ¦   +-- scanners/
¦   ¦   ¦   +-- orchestrator.py      # Multi-scanner runner & CLI entrypoint
¦   ¦   ¦   +-- crypto_scanner.py    # Source code & protocol scanner
¦   ¦   ¦   +-- certificate_scanner.py # Deep X.509 PEM/DER parser
¦   ¦   ¦   +-- dependency_scanner.py # 14 manifest/lockfile parser
¦   ¦   ¦   +-- container_scanner.py # Layer whiteouts & OS package scanner
¦   ¦   ¦   +-- binary_scanner.py    # ELF/PE/Mach-O binary header & symbol scanner
¦   ¦   ¦   +-- hsm_scanner.py       # Cloud KMS & HSM configuration scanner
¦   ¦   +-- ai/advisor.py            # AI Copilot with offline fallback
¦   +-- tests/                       # 25+ automated pytest unit/integration tests
+-- frontend/                        # React + Vite + Tailwind CSS Dashboard
+-- .github/workflows/
¦   +-- quantumshield-gate.yml       # GitHub Actions CI/CD Security Gate
+-- docker-compose.yml               # Containerized stack (API, Celery, Redis, UI)
+-- docs/
    +-- ARCHITECTURE.md
    +-- DEMO_SCRIPT.md               # 5-minute SIH presentation script
```
