# QuantumShield AI — 5-Minute Demo Script

**0:00–0:40 — Hook**
"Every organization here has a plan for today's cyberattacks. Almost none of
you have a plan for 'harvest now, decrypt later' — where an attacker
intercepts your encrypted traffic *today* and just waits for a quantum
computer to decrypt it. NIST finalized post-quantum standards last year.
The problem isn't that the migration is hard — it's that nobody knows what
to migrate, because nobody has an inventory of where RSA and ECC actually
live in their codebase. QuantumShield AI builds that inventory automatically
and tells you what to fix first."

**0:40–1:30 — Live scan**
Run the scanner against the sample vulnerable repo live in terminal:
```
python -m app.scanners.crypto_scanner backend/app/scanners/samples/demo_target
```
Point out: 13 real findings, in 4 files, in under a second — RSA/ECDSA key
generation, MD5, legacy TLS, a hardcoded AWS key, a committed private key.
"This isn't simulated output — this ran against real code just now."

**1:30–2:30 — Dashboard walkthrough**
Switch to the dashboard. Walk through:
- Overall Health score and grade
- Security Score vs. Quantum Readiness Score — explain why they're separate
- The findings table, filter to "critical"
- Point at the "harvest-risk" tag on the RSA/ECDSA findings specifically

**2:30–3:30 — AI Copilot**
Ask the copilot live: *"Which of these should I fix first and why?"*
Let it respond with prioritization reasoning grounded in the actual findings
(harvest-now risk > active auth bypass > classical weaknesses), not generic
advice.

**3:30–4:15 — Migration roadmap**
Show the generated 3-phase roadmap (0-6mo / 6-18mo / 18-36mo) — this is the
artifact a CISO takes into a budget conversation.

**4:15–5:00 — Business close**
"This is a wedge into a market with a hard compliance deadline (CNSA 2.0)
and no incumbent doing both classical and quantum scanning in one product.
We're not asking you to believe quantum computers arrive tomorrow — we're
asking you to recognize that encrypted data captured today is already at
risk, and organizations need to know where that exposure lives before they
can fix it."

## Fallback if live demo breaks
Have the dashboard screenshots and the terminal scan output (captured this
session, see `docs/SAMPLE_SCAN_OUTPUT.txt`) ready as backup slides.
