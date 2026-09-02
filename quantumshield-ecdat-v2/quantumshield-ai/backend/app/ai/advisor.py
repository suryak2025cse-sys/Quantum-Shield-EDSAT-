"""
AI Security Advisor
=====================
Provides plain-language, role-aware explanations: business impact for executives,
technical remediation for developers, and a prioritized migration roadmap for
quantum-vulnerable crypto.

Features:
  - Online mode: Uses Anthropic API (Claude) when ANTHROPIC_API_KEY is configured.
  - Offline fallback: Deterministic, rule-based expert advisor engine that runs
    without internet access or API keys, ensuring reliable demonstrations.
  - Cache: In-memory hash cache to eliminate duplicate LLM calls.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Iterable

import httpx

from app.models.schemas import Category, Finding, Severity

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-6"

_explanation_cache: dict[str, str] = {}


def _cache_key(finding: Finding) -> str:
    raw = f"{finding.matched_pattern}:{finding.severity}:{finding.category}"
    return hashlib.sha256(raw.encode()).hexdigest()


async def _call_claude(system: str, user_prompt: str, max_tokens: int = 1024) -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not configured")

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            ANTHROPIC_API_URL,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": MODEL,
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user_prompt}],
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return "".join(block.get("text", "") for block in data.get("content", []) if block.get("type") == "text")


ADVISOR_SYSTEM_PROMPT = """You are QuantumShield AI's Security Advisor. You explain security and \
post-quantum cryptography findings to two audiences at once: engineers who need precise, \
actionable remediation, and executives who need business risk framed in plain language.

Rules:
- Ground every explanation strictly in the finding data provided. Never invent CVE numbers, \
  statistics, or facts not present in the input.
- Be concise: 3-5 sentences per finding, no filler.
- For quantum-vulnerable crypto, always distinguish "harvest now, decrypt later" exposure \
  (data intercepted today, decrypted once quantum computers mature) from live protocol risk.
- Recommend NIST-standardized post-quantum algorithms (ML-KEM/FIPS 203, ML-DSA/FIPS 204, \
  SLH-DSA/FIPS 205) where applicable, not proprietary or non-standard schemes.
"""


def _generate_offline_explanation(finding: Finding) -> str:
    """Deterministic, rule-based expert explanation when offline/air-gapped."""
    title = finding.title
    cat = finding.category
    harvest = finding.quantum_harvest_now_risk
    pqc = finding.nist_pqc_recommendation or "Modern quantum-resistant primitive"

    if cat == Category.QUANTUM_VULNERABLE_CRYPTO:
        tech = (
            f"**Technical Impact:** {title} relies on asymmetric mathematical hardness (discrete logarithm or integer factorization) "
            f"that is solved in polynomial time by Shor's algorithm on a Cryptographically Relevant Quantum Computer (CRQC). "
            f"Recommended migration target is {pqc}."
        )
        biz = (
            f"**Business Impact:** {'?? HIGH HARVEST-NOW RISK: ' if harvest else ''}Adversaries intercepting network traffic or encrypted data today "
            f"can store it until quantum systems mature to decrypt it. Immediate priority for data with multi-year regulatory confidentiality requirements."
        )
    elif cat == Category.SECRET:
        tech = (
            f"**Technical Impact:** Committed private credentials ({title}) in `{finding.file_path}` expose live authorization tokens or private keys. "
            f"Immediate rotation and storage in a hardware or cloud KMS is required."
        )
        biz = (
            "**Business Impact:** Direct breach risk. Exposed secrets allow account takeover, lateral movement, and compliance violations under GDPR/HIPAA/SOC2."
        )
    elif cat == Category.CERTIFICATE_ISSUE:
        tech = (
            f"**Technical Impact:** X.509 Certificate ({title}) exhibits validity or signature weakness. "
            f"Reissue using SHA-256+ with 2048/3072-bit RSA or ECDSA P-256, preparing for dual-signature ML-DSA certificates."
        )
        biz = (
            "**Business Impact:** Risk of service outage due to certificate expiry, MITM interception, or trust store deprecation."
        )
    else:
        tech = (
            f"**Technical Impact:** {finding.description} Remediation: {finding.remediation or 'Update to recommended standard.'}"
        )
        biz = (
            f"**Business Impact:** Classified as {finding.severity.value.upper()} severity. Violates modern cryptographic security baseline standards."
        )

    return f"{tech}\n\n{biz}"


def _generate_offline_roadmap(findings: Iterable[Finding]) -> str:
    """Generates a structured 3-phase PQC migration roadmap offline."""
    quantum_findings = [f for f in findings if f.category == Category.QUANTUM_VULNERABLE_CRYPTO]
    if not quantum_findings:
        return "### PQC Migration Roadmap\n\nNo quantum-vulnerable cryptographic assets were detected in this scan."

    rsa_count = sum(1 for f in quantum_findings if "RSA" in (f.matched_pattern or "") or "RSA" in f.title)
    ecc_count = sum(1 for f in quantum_findings if "ECC" in (f.matched_pattern or "") or "EC" in f.title)
    dh_count = sum(1 for f in quantum_findings if "DH" in (f.matched_pattern or "") or "Diffie" in f.title)

    return f"""### ??? Quantum-Safe Migration Roadmap (NIST FIPS 203 / 204 / 205)

**Identified Quantum Exposures:** {len(quantum_findings)} assets ({rsa_count} RSA, {ecc_count} ECC/ECDSA, {dh_count} Diffie-Hellman)

---

#### ?? Phase 1: Immediate Triage & Harvest-Now Defense (Months 0 – 6)
- **Target:** External endpoints, session key establishment, and long-retention encrypted databases.
- **Action:**
  - Deprecate static RSA key exchange in favor of ephemeral hybrid **X25519 + ML-KEM-768 (FIPS 203)**.
  - Rotate exposed credentials and legacy certificates expiring within 90 days.
  - Enforce TLS 1.3 with PQC hybrid ciphersuite negotiation where client support exists.
- **Milestone:** Elimination of high-exposure Harvest-Now-Decrypt-Later attack surfaces.

---

#### ?? Phase 2: Core Infrastructure & Protocol Upgrades (Months 6 – 18)
- **Target:** Internal microservice authentication (mTLS), JWT token signing, and crypto libraries.
- **Action:**
  - Upgrade dependencies (`cryptography >= 42.0`, `BouncyCastle >= 1.78`, `OpenSSL 3.5+`) for native PQC support.
  - Transition JWT signing from RS256/ES256 to hybrid / **ML-DSA-65 (FIPS 204)**.
  - Implement crypto-agility abstraction layers to decouple business logic from specific algorithms.
- **Milestone:** 80% reduction in quantum-vulnerable blast radius across services.

---

#### ?? Phase 3: Hardware & Full PKI Standardization (Months 18 – 36)
- **Target:** Root CAs, Hardware Security Modules (HSMs), long-term digital document archives.
- **Action:**
  - Deploy dual-signature root and intermediate X.509 CAs supporting **ML-DSA** and **SLH-DSA (FIPS 205)**.
  - Update Cloud KMS / HSM firmware with post-quantum key management profiles.
  - Achieve full compliance with CNSA 2.0 and NIST PQC migration mandates.
- **Milestone:** 100% Post-Quantum Cryptographic Agility verified in CI/CD pipeline.
"""


def _generate_offline_chat(question: str, scan_context: dict) -> str:
    """Answers natural language questions grounded in scan context offline."""
    q = question.lower()
    total = scan_context.get("total_findings", 0)
    scores = scan_context.get("scores", {})
    health = scores.get("overall_health", "N/A")
    grade = scores.get("grade", "N/A")
    findings = scan_context.get("findings", [])

    if any(w in q for w in ["fix first", "prioritize", "priority", "critical"]):
        criticals = [f for f in findings if f.get("severity") in ("critical", "high")]
        top_list = "\n".join([f"- **{f.get('title')}** in `{f.get('file_path')}` ({f.get('severity', '').upper()})" for f in criticals[:4]])
        return (
            f"Based on risk scoring and Harvest-Now-Decrypt-Later exposure, prioritize these findings first:\n\n"
            f"{top_list or 'No critical findings detected.'}\n\n"
            f"**Recommendation:** Address hardcoded secrets and active auth flaws immediately, followed by replacing RSA/ECC with ML-KEM."
        )

    if any(w in q for w in ["quantum", "harvest", "pqc", "nist"]):
        q_findings = [f for f in findings if f.get("category") == "quantum_vulnerable_crypto"]
        return (
            f"This project contains **{len(q_findings)} quantum-vulnerable cryptographic assets**. "
            f"Under Shor's algorithm, these algorithms (RSA, ECDSA, ECDH) can be broken by cryptographically relevant quantum computers. "
            f"NIST recommends migrating to **ML-KEM (FIPS 203)** for key encapsulation and **ML-DSA (FIPS 204)** for digital signatures."
        )

    if any(w in q for w in ["score", "grade", "health", "overview"]):
        return (
            f"The overall health score for **{scan_context.get('target_name', 'project')}** is **{health}/100** (Grade: **{grade}**). "
            f"There are **{total} total findings**, with {scores.get('security_score', 'N/A')}/100 Security Score and "
            f"{scores.get('quantum_readiness_score', 'N/A')}/100 Quantum Readiness Score."
        )

    if any(w in q for w in ["mosca", "x+y", "threat horizon"]):
        at_risk = scan_context.get("mosca_at_risk_count", 0)
        return (
            f"Mosca's theorem ($X + Y > Z$) flags **{at_risk} assets at risk**. "
            f"If your data security lifetime ($X$) plus migration duration ($Y$) exceeds the estimated time until quantum supremacy ($Z$), "
            f"adversaries can capture encrypted data today and decrypt it in the future."
        )

    # General fallback
    return (
        f"QuantumShield AI scanned **{scan_context.get('target_name', 'project')}** and identified **{total} findings** "
        f"across {scan_context.get('files_scanned', 0)} files with an overall health grade of **{grade}**.\n\n"
        f"You can explore the **Findings**, **Dependency Graph**, **PQC Validation**, and **Remediation Plan** tabs in the dashboard for detailed guidance."
    )


async def explain_finding(finding: Finding) -> str:
    """Explain a single finding, using cache and graceful fallback."""
    key = _cache_key(finding)
    if key in _explanation_cache:
        return _explanation_cache[key]

    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            prompt = f"""Explain this finding for both a developer and an executive audience.

Finding: {finding.title}
Category: {finding.category.value}
Severity: {finding.severity.value}
Description: {finding.description}
CWE: {finding.cwe_id or 'N/A'}
Quantum harvest-now-decrypt-later risk: {finding.quantum_harvest_now_risk}
Suggested NIST PQC recommendation: {finding.nist_pqc_recommendation or 'N/A'}

Respond in two short paragraphs: "Technical impact:" then "Business impact:"."""
            explanation = await _call_claude(ADVISOR_SYSTEM_PROMPT, prompt, max_tokens=400)
            _explanation_cache[key] = explanation
            return explanation
        except Exception:
            pass  # Fall back to offline generator

    explanation = _generate_offline_explanation(finding)
    _explanation_cache[key] = explanation
    return explanation


async def generate_migration_roadmap(findings: Iterable[Finding]) -> str:
    """Generate a prioritized PQC migration roadmap."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            quantum_findings = [f for f in findings if f.category.value == "quantum_vulnerable_crypto"]
            if not quantum_findings:
                return "No quantum-vulnerable cryptography detected in this scan."
            summarized = [
                {
                    "rule": f.matched_pattern,
                    "title": f.title,
                    "severity": f.severity.value,
                    "file": f.file_path,
                    "harvest_now_risk": f.quantum_harvest_now_risk,
                    "recommendation": f.nist_pqc_recommendation,
                }
                for f in quantum_findings
            ]
            prompt = f"""Given these quantum-vulnerable cryptography findings, produce a 3-phase migration roadmap.
Findings:
{json.dumps(summarized, indent=2)}"""
            return await _call_claude(ADVISOR_SYSTEM_PROMPT, prompt, max_tokens=1200)
        except Exception:
            pass

    return _generate_offline_roadmap(findings)


async def chat_with_advisor(question: str, scan_context: dict) -> str:
    """Powers the AI Security Copilot chat."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            prompt = f"""The user is asking about their security scan results. Answer using only the context below:
Scan context:
{json.dumps(scan_context, indent=2, default=str)}

User question: {question}"""
            return await _call_claude(ADVISOR_SYSTEM_PROMPT, prompt, max_tokens=600)
        except Exception:
            pass

    return _generate_offline_chat(question, scan_context)
