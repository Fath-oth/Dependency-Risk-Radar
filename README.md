# 🛡️ Dependency Risk Radar

**SBOM generation · CVE analysis · Licence risk · AI-powered update plan**

Dependency Risk Radar automatically audits Android/Java project dependencies, generates a standards-compliant SBOM, and produces a multicriteria risk score enriched by AI recommendations.

[![Website](https://img.shields.io/badge/Website-website--radar.vercel.app-blue?style=flat-square&logo=vercel&logoColor=white)](https://website-radar.vercel.app)
---

## Features

| Feature | Description |
|---|---|
| **SBOM** | CycloneDX 1.5 (JSON/XML) and SPDX 2.3 (JSON) |
| **CVE scoring** | OSV.dev + NVD, CVSS v3, fix availability |
| **Obsolescence** | Maven Central — version gap + release age |
| **Licence risk** | SPDX matrix, copyleft detection, conflict analysis |
| **Trackers** | Exodus Privacy database, permission analysis |
| **Transitive risk** | networkx DAG — risk propagation with depth decay |
| **AI Update Plan** | Claude AI — prioritised updates with migration notes |
| **Dashboard** | React + D3.js interactive dependency graph |
| **CI/CD** | CLI with `--fail-threshold` for pipeline gates |

---

## Quick Start

### With Docker (recommended)

```bash
# 1. Clone and configure
git clone https://github.com/your-org/dependency-risk-radar
cd dependency-risk-radar
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY

# 2. Start all services
docker-compose up -d

# 3. Open the dashboard
open http://localhost:3000
```

### CLI (local Python)

```bash
# Install dependencies
cd backend
pip install -r requirements.txt

# Analyse a Gradle project
python cli/drr.py analyze /path/to/android-project

# Analyse an APK
python cli/drr.py analyze /path/to/app.apk

# With CI/CD gate (fails if score > 75 or any CRITICAL CVE)
python cli/drr.py analyze ./project --fail-threshold 75 --fail-on-critical

# List saved reports
python cli/drr.py list

# View a report
python cli/drr.py report <report-id>
```

---

## Architecture

```
dependency-risk-radar/
├── backend/                  # Python / FastAPI
│   ├── app/
│   │   ├── api/main.py       # REST API + WebSocket endpoints
│   │   ├── core/
│   │   │   ├── models.py     # Component, CVE, License, RiskScores
│   │   │   ├── config.py     # Settings (pydantic-settings)
│   │   │   └── pipeline.py   # Main orchestrator
│   │   ├── ingestion/
│   │   │   ├── gradle_parser.py   # build.gradle + tree resolver
│   │   │   ├── apk_analyzer.py    # androguard-based APK analysis
│   │   │   └── enricher.py        # OSV, Maven Central, Exodus, ClearlyDefined
│   │   ├── scoring/engine.py      # CVE + obsolescence + licence + tracker
│   │   ├── graph/dependency_graph.py  # networkx DAG + transitive risk
│   │   ├── ai/planner.py          # Claude API — update plan + narrator
│   │   ├── sbom/generator.py      # CycloneDX + SPDX generation
│   │   └── exporters/pdf_exporter.py  # PDF + CSV export
│   └── tests/                # pytest — 80+ test cases
│
├── frontend/                 # React / Vite
│   ├── src/
│   │   ├── App.jsx           # Router + layout + upload flow
│   │   ├── stores/useStore.js    # Zustand global state
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx     # Overview, charts, stats
│   │   │   ├── Explorer.jsx      # Filterable component table
│   │   │   ├── GraphView.jsx     # D3.js force-directed graph
│   │   │   └── UpdatePlan.jsx    # AI update plan display
│   │   └── components/shared.jsx # RiskBadge, ScoreBar, StatCard...
│
├── cli/drr.py                # Command-line interface
├── docker-compose.yml        # Full stack orchestration
└── .env.example              # Environment template
```

---

## Risk Scoring Formula

```
Global Score = CVE×0.45 + Obsolescence×0.25 + Licence×0.20 + Tracker×0.10
```

| Score | Level | Action |
|---|---|---|
| 0–19 | 🟢 Low | Standard monitoring |
| 20–49 | 🟡 Moderate | Update in next sprint |
| 50–74 | 🟠 High | Update within 2 weeks |
| 75–89 | 🔴 Critical | Immediate update |
| 90–100 | ⛔ Blocking | Block deployment |

### CVE Component
- Base: CVSS v3 score normalised to 100
- +5 per unpatched vulnerability (max +15)
- +2 per CVE count (max +10)
- +10 if known public exploit

### Obsolescence Component
- +50 if major version behind
- +25 if minor version behind
- +10 if patch version behind
- +50 if no release in 4+ years, +40 for 2–4 years

### Licence Risk Table
| Licence | Score |
|---|---|
| MIT / Apache 2.0 | 0 |
| BSD 2/3-Clause | 5 |
| MPL 2.0 | 20 |
| LGPL 2.1/3.0 | 35 |
| GPL 2.0/3.0 | 75 |
| AGPL 3.0 | 90 |
| Unknown | 65 |

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `POST /api/v1/analyze/gradle` | POST | Analyse a Gradle project path |
| `POST /api/v1/analyze/apk` | POST | Upload and analyse an APK |
| `GET /api/v1/jobs/{id}` | GET | Poll analysis job status |
| `WS /ws/analyze/{id}` | WS | Real-time progress stream |
| `GET /api/v1/reports` | GET | List all reports |
| `GET /api/v1/reports/{id}` | GET | Full report data |
| `GET /api/v1/reports/{id}/components` | GET | Paginated/filtered components |
| `GET /api/v1/reports/{id}/graph` | GET | D3-ready graph JSON |
| `GET /api/v1/reports/{id}/update-plan` | GET | AI update plan |
| `GET /api/v1/reports/{id}/sbom?format=cyclonedx` | GET | Download SBOM |

---

## Running Tests

```bash
cd backend
pip install -r requirements.txt
pytest

# With coverage
pytest --cov=app --cov-report=html
open htmlcov/index.html
```

Tests cover:
- **Scoring engine** — all 4 dimensions, edge cases, weight validation
- **Gradle parser** — DSL forms, variable substitution, tree parsing, deduplication
- **Graph module** — build, transitive propagation, risk paths, ego graphs
- **SBOM generator** — CycloneDX and SPDX structure, fields, uniqueness
- **Enricher** — OSV parsing, licence matrix, tracker detection

---

## GitHub Actions Integration

```yaml
# .github/workflows/security.yml
name: Dependency Security Check
on: [push, pull_request]

jobs:
  dependency-risk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install -r backend/requirements.txt
      - run: |
          python cli/drr.py analyze . \
            --fail-threshold 75 \
            --fail-on-critical \
            --output ./drr_reports
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: drr-report
          path: drr_reports/
```

---

## Data Sources

| Source | Data | Rate limit |
|---|---|---|
| [OSV.dev](https://osv.dev) | CVE/vulnerability data | Unlimited (no key needed) |
| [NVD NIST](https://nvd.nist.gov) | CVSS scores | 5 req/30s (50 with free key) |
| [Maven Central](https://search.maven.org) | Latest versions, dates | Generous |
| [ClearlyDefined](https://clearlydefined.io) | Licence resolution | Unlimited |
| [Exodus Privacy](https://exodus-privacy.eu.org) | Android trackers DB | Unlimited |

---

## Academic Context

This project demonstrates:

1. **Static analysis pipeline** — multi-source ingestion, normalisation, enrichment
2. **Graph algorithms** — DAG construction, transitive closure, weighted risk propagation
3. **Multicriteria scoring** — weighted aggregation with domain-calibrated parameters
4. **LLM integration** — structured output prompting, fallback strategies, prompt engineering
5. **Software supply chain security** — SBOM standards (CycloneDX, SPDX), CVSS v3

### Evaluation Metrics
- SBOM completeness rate (% components with all fields populated)
- CVE detection precision vs manual audit baseline
- AI recommendation quality (human evaluation 1–5)
- Analysis time vs project size (50 / 200 / 500 components)

---

## License

MIT — see [LICENSE](LICENSE)
