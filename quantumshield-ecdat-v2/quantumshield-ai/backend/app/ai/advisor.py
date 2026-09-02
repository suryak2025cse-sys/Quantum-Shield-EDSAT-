"""
AI Security Advisor
=====================
Wraps calls to Claude (via the Anthropic API) to turn raw findings into
plain-language, role-aware explanations: business impact for executives,
technical remediation for developers, and a prioritized migration roadmap
for the quantum-vulnerable crypto findings specifically.

Design choices:
  - We batch findings per request (grouped by category) rather than one
    call per finding, to control latency and cost on large scans.
  - Responses are cached by a hash of (rule_id + severity) since the same
    rule firing in 40 files doesn't need 40 separate LLM explanations —
    only the file/line context differs, which we template in afterward.
  - All prompts are grounded with the actual Finding data (no hallucinated
    CVEs) — the model explains and prioritizes, it does not invent facts.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Iterable

import httpx

from app.models.schemas import Finding

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


async def explain_finding(finding: Finding) -> str:
    """Explain a single finding, using cache to avoid redundant calls for repeat rule hits."""
    key = _cache_key(finding)
    if key in _explanation_cache:
        return _explanation_cache[key]

    prompt = f"""Explain this finding for both a developer and an executive audience.

Finding: {finding.title}
Category: {finding.category.value}
Severity: {finding.severity.value}
Description: {finding.description}
CWE: {finding.cwe_id or "N/A"}
Quantum harvest-now-decrypt-later risk: {finding.quantum_harvest_now_risk}
Suggested NIST PQC recommendation: {finding.nist_pqc_recommendation or "N/A"}

Respond in two short paragraphs: "Technical impact:" then "Business impact:"."""

    explanation = await _call_claude(ADVISOR_SYSTEM_PROMPT, prompt, max_tokens=400)
    _explanation_cache[key] = explanation
    return explanation


async def generate_migration_roadmap(findings: Iterable[Finding]) -> str:
    """Generate a prioritized PQC migration roadmap across all quantum-vulnerable findings."""
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

    prompt = f"""Given these quantum-vulnerable cryptography findings from a codebase scan, produce a \
prioritized migration roadmap with 3 phases (0-6 months, 6-18 months, 18-36 months). For each phase, \
list what to migrate, why it's prioritized at that stage (data sensitivity, harvest-now risk, blast \
radius), and the target NIST PQC standard. Base this only on the findings given, don't invent new ones.

Findings:
{json.dumps(summarized, indent=2)}
"""
    return await _call_claude(ADVISOR_SYSTEM_PROMPT, prompt, max_tokens=1200)


async def chat_with_advisor(question: str, scan_context: dict) -> str:
    """Powers the AI Security Copilot chat — answers natural-language questions
    grounded in the current scan's findings and scores."""
    prompt = f"""The user is asking about their security scan results. Answer using only the \
context below; if the answer isn't in the context, say what additional scan or data would be needed.

Scan context:
{json.dumps(scan_context, indent=2, default=str)}

User question: {question}
"""
    return await _call_claude(ADVISOR_SYSTEM_PROMPT, prompt, max_tokens=600)
