# TrustGraph — Third-Party Software Trust Intelligence

TrustGraph is a live-first software supply-chain risk intelligence prototype. The default workspace starts empty; users import an actual dependency inventory and query OSV.dev for published advisories. A separate simulation mode loads a seeded fictional enterprise environment for repeatable demonstrations.

**Live demo:** https://trustgraph-eight.vercel.app  
**Backend API:** https://trustgraph-api-gx1g.onrender.com  
**Interactive API documentation:** https://trustgraph-api-gx1g.onrender.com/docs

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
- Separate simulation mode with seeded multi-application demonstration inventory.
- Import ZIP, package-lock.json, package.json, requirements.txt and CycloneDX JSON.
- Explainable risk prioritization and remediation status tracking.
- JSON and CSV report export.
- Primary live vulnerability matching through OSV.dev (`POST /api/osv/check`), requiring backend internet access. Results populate the main Risk findings and Response centre.
- One-click demo reset.

## Important accuracy notes

- Built-in `TG-DEMO-*` advisories are synthetic examples, not real CVE records; they appear only in simulation mode.
- Live OSV.dev results are the findings shown in live mode. Simulation mode uses its separate synthetic catalogue.
- The TrustGraph 2.0 incident scenario is simulated; it does not detect actual compromise.
- Risk scores are transparent prioritization heuristics, not probabilities of exploitation.
- Import replaces the active in-memory inventory. Backend restart resets inventory and remediation actions.
- CycloneDX import is a basic component-list reader, not full validated SBOM support.
- Dependency topology is manifest-level, not a source-code call graph or runtime reachability engine.
- This MVP does not scan binaries, containers, source code, vendor posture or runtime traffic.

## Run locally

Prerequisites: Python 3.10+ and Node.js 18+.

Backend (terminal 1):
```bash
cd backend
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Frontend (terminal 2):
```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. API docs: http://localhost:8000/docs.

The frontend reads `VITE_API_URL` at build time and defaults to `http://localhost:8000`. For local development, copy `frontend/.env.example` to `frontend/.env.local` if you need to override the API URL. For the hosted frontend, configure `VITE_API_URL=https://trustgraph-api-gx1g.onrender.com` in the Vercel project's environment variables and redeploy. The backend optionally accepts additional comma-separated CORS origins through `TRUSTGRAPH_ALLOWED_ORIGINS`; see `backend/.env.example`.

## Deployment

- Frontend: Vercel — https://trustgraph-eight.vercel.app
- Backend: Render — https://trustgraph-api-gx1g.onrender.com
- API health endpoint: https://trustgraph-api-gx1g.onrender.com/api/health
- API documentation: https://trustgraph-api-gx1g.onrender.com/docs

The backend must be reachable from the browser and have outbound internet access for live OSV.dev lookups. On Render's free tier, the service may take a short time to wake after inactivity.

## Recommended demo

1. Start in the empty Live workspace.
2. Import a real `package-lock.json`, `requirements.txt` or CycloneDX SBOM.
3. Let TrustGraph query OSV.dev and populate Risk findings with published advisory IDs.
4. Open a finding and inspect its OSV source link, package version and available fixed-version guidance.
5. Explain that risk scores combine advisory severity when available with business context; they are prioritization heuristics.
6. Use **Run simulation** only for the repeatable Northstar Commerce demonstration and compromised-package scenario.

## Verification checklist

Before presenting a build, verify these flows in the deployed application:

- [ ] The frontend loads and the Overview page renders.
- [ ] The backend health endpoint responds.
- [ ] A supported dependency manifest imports successfully.
- [ ] A live OSV.dev scan returns findings when matching advisories exist.
- [ ] Switching to simulation loads the labelled demo workspace.
- [ ] Returning to Live restores the live workspace for the current backend process.
- [ ] JSON and CSV exports download successfully.

This checklist is a manual acceptance guide, not a claim that every item has been independently tested in every deployment.

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
| POST | `/api/demo/reset` | Load the synthetic simulation workspace |
| POST | `/api/live/reset` | Return to an empty live workspace |
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
