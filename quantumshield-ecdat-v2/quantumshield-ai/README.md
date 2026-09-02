# QuantumShield AI
### AI-Powered Security & Quantum Readiness Platform

QuantumShield AI scans codebases for today's security vulnerabilities *and*
tomorrow's quantum-computing risk in one pass — producing a Security Score,
a Quantum Readiness Score, AI-generated explanations, and a prioritized
post-quantum migration roadmap.

> **Read this first:** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) has an
> explicit table of what's fully functional in this build vs. scaffolded for
> the next milestone. Nothing below is oversold.

## What actually works right now

- **Real static-analysis scanner** (`backend/app/scanners/crypto_scanner.py`)
  detecting hardcoded secrets (AWS/GCP/Azure keys, private key material),
  quantum-vulnerable crypto (RSA, ECC/ECDSA, Diffie-Hellman), classical
  weaknesses (MD5, SHA-1, legacy TLS, ECB mode), and JWT misconfiguration —
  tested against a real sample vulnerable repo, output captured in
  [`docs/SAMPLE_SCAN_OUTPUT.txt`](docs/SAMPLE_SCAN_OUTPUT.txt).
- **Deterministic scoring engine** turning findings into four weighted 0–100
  scores plus a letter grade.
- **AI Advisor** (`backend/app/ai/advisor.py`) — real Claude API integration
  for per-finding explanations, migration roadmap generation, and a
  natural-language copilot chat, grounded strictly in scan data.
- **FastAPI REST API**, runnable standalone.
- **React dashboard** (`frontend/`, also exported standalone as
  `quantumshield_dashboard.jsx`) matching the exact API response shape.

## Quick start

### Backend
```bash
cd backend
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...   # required only for AI explain/roadmap/chat endpoints
uvicorn app.main:app --reload
# -> http://localhost:8000/docs (OpenAPI UI)
```

### Try the scanner directly (no server needed)
```bash
cd backend
python3 -c "
from app.scanners.crypto_scanner import scan_directory
from app.scoring.engine import compute_scores
findings, files = scan_directory('app/scanners/samples/demo_target')
print(f'{len(findings)} findings across {files} files')
print(compute_scores(findings))
"
```

### Frontend
```bash
cd frontend
npm install
npm run dev
# -> http://localhost:5173
```

### Full stack via Docker
```bash
docker compose up --build
```

## Project structure

```
quantumshield-ai/
├── backend/
│   └── app/
│       ├── main.py              # FastAPI entrypoint
│       ├── api/routes.py        # REST endpoints
│       ├── scanners/            # Detection engines (crypto/secrets)
│       │   └── samples/demo_target/  # Intentionally vulnerable sample repo
│       ├── scoring/engine.py    # Security/Quantum/Compliance scoring math
│       ├── ai/advisor.py        # Claude API integration
│       ├── reports/generator.py # Executive/technical/migration reports
│       ├── models/schemas.py    # Pydantic data contracts
│       └── core/config.py
├── frontend/                    # React + Vite + Tailwind dashboard
├── docs/
│   ├── ARCHITECTURE.md
│   ├── BUSINESS.md              # Business model, revenue, competitors, roadmap, judge Q&A
│   ├── DEMO_SCRIPT.md
│   └── SAMPLE_SCAN_OUTPUT.txt
├── .github/workflows/ci.yml
└── docker-compose.yml
```

## Documentation index

| Doc | Contents |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, what's real vs. scaffolded, scanner extensibility pattern, why quantum simulation isn't literally in the product |
| [BUSINESS.md](docs/BUSINESS.md) | Target market, competitive landscape, revenue model, cost structure, GTM, roadmap, judge Q&A |
| [DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) | 5-minute hackathon demo walkthrough |

## Design system

Dark enterprise theme — near-black background (`#05060B`), indigo/violet
primary accent, cyan secondary accent (the "quantum" signal color),
glassmorphic cards with backdrop blur. Typography: Space Grotesk (display),
Inter (body), JetBrains Mono (code/data). Full token rationale is in the
dashboard component comments.

## Honest limitations (also worth saying to judges before they ask)

- Dependency CVE scanning, certificate chain parsing, and GitHub PR
  integration are architected but not implemented — see the roadmap in
  BUSINESS.md.
- Scan storage is in-memory in this build (swap to MongoDB is straightforward
  given the existing Motor/docker-compose wiring, but wasn't the priority for
  a working demo).
- Cost estimates in BUSINESS.md are illustrative, not based on production
  usage data.
