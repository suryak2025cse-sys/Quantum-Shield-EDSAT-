# QuantumShield AI � SIH Live Demo Script & Runbook

This guide contains the exact steps and scripts to deliver a winning **5-minute live demo** of QuantumShield AI on Windows PowerShell or Linux/macOS.

---

## Quick Setup & Launch Commands

### 1. Launch Backend (Terminal 1)
> Verify health at `http://localhost:8000/health`

---

### 2. Launch Frontend (Terminal 2)
> Open browser at `http://localhost:5173`

---

## 5-Minute SIH Demo Flow

### 0:00�0:45 | Hook & Problem Statement
- **Narrative:**
  > *"Every organization here scans for known CVEs. But almost nobody has an automated inventory of where asymmetric cryptography lives across their code, certificates, dependencies, and containers.*
  > *With Harvest-Now, Decrypt-Later (HNDL) attacks and NIST's finalized PQC standards (FIPS 203, 204, 205), organizations face compliance deadlines (CNSA 2.0). QuantumShield AI provides an automated Cryptographic Bill of Materials (CBOM), Mosca risk assessment, and phased PQC migration planning."*

---

### 0:45�1:45 | Live CLI & CycloneDX 1.6 CBOM
Demonstrate the stand-alone CLI runner live.
- Highlight:
  - Discovered 13+ cryptographic findings and dependencies in under 1 second.
  - Generates official **CycloneDX 1.6 JSON CBOM** with component dependency trees.
  - Zero cloud dependencies required; operates fully offline.

---

### 1:45�2:45 | Interactive Web Dashboard Walkthrough
Switch to `http://localhost:5173` and upload `demo_target.zip` (or scan sample repo):
1. **Executive Overview**:
   - Distinct **Security Score** (classical vulnerabilities) vs. **Quantum Readiness Score** (Shor's algorithm exposure).
2. **Normalized CBOM Inventory**:
   - Unified assets deduplicated across files with stable fingerprints.
3. **Mosca Inequality ($X + Y > Z$)**:
   - Data Lifetime ($X$) + Migration Duration ($Y$) compared against CRQC Threat Horizon ($Z$).
   - Show sensitivity matrix across $Z=5, 10, 15, 20$ years.
4. **Blast Radius & Crypto Agility**:
   - Identifies whether cryptography is modular or tightly coupled across dependent services.

---

### 2:45�3:45 | PQC Migration Validator & What-If Simulation
1. **NIST PQC Migration Engine**:
   - Recommends NIST FIPS 203 (ML-KEM-768 hybrid) for key exchange and FIPS 204 (ML-DSA) for signatures.
   - Estimates migration effort (hours), latency impact (+ms), and cost range.
2. **What-If Impact Simulator**:
   - Select and resolve the RSA/ECC and weak JWT findings.
   - Watch the overall health score dynamically update from Grade D to Grade A in real time.

---

### 3:45�4:30 | Offline AI Copilot & Remediation Tickets
1. **Deterministic AI Advisor**:
   - Ask: *"Which finding should I prioritize first for HNDL risk?"*
   - Explains cryptographic blast radius and remediation with zero external API key needed.
2. **Exportable Remediation Tickets**:
   - Export structured Jira/GitHub Markdown tickets with step-by-step code fixes and NIST compliance references.

---

### 4:30�5:00 | CI/CD Security Gate & Close
Demonstrate the CI/CD pipeline gate.
- Blocks commits introducing quantum-vulnerable primitives without agility wrappers.
- Exports SARIF 2.1.0 directly for GitHub Code Scanning integration.

---

## Backup Offline Fallback
If live network or Docker is unavailable:
- Use the offline scanner mode.
- Use the built-in deterministic AI fallback for all advisor explanations and roadmaps.
