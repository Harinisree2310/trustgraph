# TrustGraph — Third-Party Software Trust Intelligence

TrustGraph is a hackathon MVP for software supply-chain risk intelligence.

## TrustGraph 2.0 — incident-to-business-impact workflow

The 2.0 increment adds an incident analysis flow. Given a reported or simulated compromised package, the backend matches it against the current inventory, follows declared reverse dependency edges, groups potentially impacted components by application and business service, calculates an explainable triage score, and returns a structured response plan.

- New UI: **Incident analysis**.
- New API: `POST /api/incidents/analyze` and `GET /api/incidents/demo`.
- Impact mapping is based on inventory and manifest-level relationships; it does not prove runtime reachability.
- Demo mode is explicitly labelled simulated. A reported incident assessment is not confirmation that compromise occurred.
- Risk scores are triage heuristics, not exploit probabilities or financial-loss predictions.
- CORS supports local development and Vercel deployments; use `TRUSTGRAPH_ALLOWED_ORIGINS` for additional trusted origins.

See [problem statement](docs/TRUSTGRAPH_2_0_PROBLEM_STATEMENT.md), [architecture](docs/TRUSTGRAPH_2_0_ARCHITECTURE.md), and [judge demo script](docs/TRUSTGRAPH_2_0_DEMO_SCRIPT.md).

## Existing capabilities

- React + Vite frontend: Overview, Risk findings, Dependency map, Inventory, Response centre and Incident analysis.
- FastAPI backend with JSON APIs.
- Seeded multi-application demonstration inventory.
- Import ZIP, package-lock.json, package.json, requirements.txt and CycloneDX JSON.
- Explainable risk prioritization and remediation status tracking.
- JSON and CSV report export.
- Optional live OSV.dev query endpoint (`POST /api/osv/check`), requiring backend internet access.
- One-click demo reset.

## Important accuracy notes

- Built-in `TG-DEMO-*` advisories are synthetic examples, not real CVE records.
- Live OSV.dev results are separate from synthetic demo findings.
- The TrustGraph 2.0 incident scenario is simulated; it does not detect actual compromise.
- Risk scores are transparent prioritization heuristics, not probabilities of exploitation.
- Import replaces the active in-memory inventory. Backend restart resets inventory and remediation actions.
- CycloneDX import is a basic component-list reader, not full validated SBOM support.
- Dependency topology is manifest-level, not a source-code call graph or runtime reachability engine.
- This MVP does not scan binaries, containers, source code, vendor posture or runtime traffic.

## Run locally

Backend:
```bash
cd backend
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Frontend (second terminal):
```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. API docs: http://localhost:8000/docs.

For hosted frontend deployment, set Vercel environment variable `VITE_API_URL` to the backend base URL. Backend CORS must allow the frontend origin.

## Recommended demo

1. Open Overview and show the seeded inventory.
2. Open **Incident analysis**.
3. Click **Run compromised-package demo**.
4. Explain matching package records and potential dependent components.
5. Show affected applications and business services.
6. Explain transparent risk factors and score.
7. Walk through the response plan.
8. Distinguish simulated incident data from live OSV.dev vulnerability intelligence.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | API health |
| GET | `/api/overview` | Dashboard metrics |
| GET | `/api/inventory` | Component inventory |
| GET | `/api/findings` | Risk findings |
| GET | `/api/graph` | Application/package topology |
| GET | `/api/actions` | Remediation statuses |
| PATCH | `/api/actions/{finding_id}` | Update remediation status |
| POST | `/api/scan` | Upload dependency manifest |
| POST | `/api/demo/reset` | Restore seeded demo |
| POST | `/api/osv/check` | Optional live OSV query |
| POST | `/api/incidents/analyze` | Analyze incident against inventory |
| GET | `/api/incidents/demo` | Deterministic simulated incident |
| GET | `/api/export/json` | Export report |
| GET | `/api/export/csv` | Export findings |

## Next engineering increments

1. Persist workspaces, incidents and actions in a database.
2. Validate CycloneDX versions and preserve PURLs, hashes, licenses and dependency edges.
3. Add provenance and signed advisory-feed ingestion.
4. Add source repository, container and artifact scanning.
5. Add call-graph/reachability analysis with explicit confidence.
6. Add trusted malicious-package and provenance signals.
7. Add authentication, authorization, tenant isolation and audit logging.
8. Add automated known-positive and known-negative tests.
