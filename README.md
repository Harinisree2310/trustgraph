
# TrustGraph — Third-Party Software Trust Intelligence

TrustGraph is a working hackathon MVP for **PS05: AI-Powered Cybersecurity**. It helps organizations understand software supply-chain exposure by importing dependency inventories, matching components against vulnerability intelligence, mapping affected applications, prioritizing remediation and exporting reports.

## What works in this prototype

- React + Vite frontend with responsive enterprise UI.
- FastAPI backend with clean JSON APIs and CORS configuration.
- Seeded multi-application demonstration inventory.
- Import `.zip`, `package-lock.json`, `package.json`, `requirements.txt`, and CycloneDX JSON (`bom.json`).
- Package inventory with ecosystem, version, direct/transitive classification and license fields where available.
- Explainable risk prioritization using severity, business criticality, exposure and dependency role.
- Risk findings, application exposure view, dependency topology, remediation queue and status updates.
- JSON and CSV report export.
- Optional live OSV.dev query endpoint (`POST /api/osv/check`), requiring internet access from the machine running the backend.
- One-click demo reset and sample manifests.

## Important data and accuracy notes

- The built-in `TG-DEMO-*` advisory catalogue is **synthetic demonstration data**, not a live vulnerability feed and not real CVE records. It exists to make the end-to-end demo deterministic.
- Use **Live OSV check** to query OSV.dev for package/version advisories. This is optional and requires outbound internet access. The live OSV response is shown separately; it does not silently overwrite the demo findings.
- The risk score is a transparent prioritization heuristic, not a probability of exploitation. Validate reachability, exploit preconditions, deployment presence and vendor advisories before taking action.
- Import currently replaces the active workspace inventory. Use Restore demo scenario to return to the seeded multi-application demo.
- CycloneDX import is a basic component-list reader. The export is a TrustGraph assessment report, not a validated CycloneDX CBOM.
- Dependency topology uses manifest-level relationships and seeded application mappings. It is not a full source-code call graph or runtime reachability engine.
- This MVP does not scan binaries, containers, source code, vendor posture or runtime traffic.

## Run locally

### 1. Backend

Python 3.10+ recommended.

```bash
cd backend
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

API docs: http://localhost:8000/docs

### 2. Frontend

Open a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173

If the API is hosted elsewhere, set `VITE_API_URL` before starting Vite, e.g. `VITE_API_URL=http://127.0.0.1:8000`.

## Demo flow (recommended)

1. Open the app. The seeded workspace loads automatically.
2. Show Overview: 16 components, multi-application exposure and risk findings.
3. Open Risk findings and click the `log4j-core` or `lodash` finding.
4. Show why it was prioritized and the recommended fixed version.
5. Open Dependency map and explain how a transitive dependency can affect a business-critical service.
6. Open Response centre and change a finding to `In progress`, then `Resolved`.
7. Export JSON or CSV.
8. Import `sample-data/requirements.txt` or `sample-data/package.json` to demonstrate scanning a real manifest.
9. Optionally run Live OSV check if internet is available.
10. Restore demo scenario.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | API health |
| GET | `/api/overview` | Dashboard metrics |
| GET | `/api/inventory` | Component inventory |
| GET | `/api/findings` | Risk findings |
| GET | `/api/graph` | Application/package topology |
| GET | `/api/actions` | Remediation statuses |
| PATCH | `/api/actions/{finding_id}` | Update remediation status |
| POST | `/api/scan` | Upload and parse manifest/ZIP |
| POST | `/api/demo/reset` | Restore seeded demo |
| POST | `/api/osv/check` | Optional live OSV.dev query |
| GET | `/api/export/json` | Export full report |
| GET | `/api/export/csv` | Export findings CSV |

## Architecture

```text
Browser (React + Vite)
  ├── Overview / Risk register / Dependency map
  ├── Inventory / Response centre
  ├── Upload and export interactions
  └── REST API calls
          |
          v
FastAPI service
  ├── Manifest parsers (npm / PyPI / CycloneDX / ZIP)
  ├── Inventory normalizer
  ├── Advisory matching (synthetic demo catalogue)
  ├── Explainable risk scoring
  ├── Remediation workflow state
  ├── JSON / CSV reporting
  └── Optional OSV.dev live query
```

## Suggested next engineering increments

1. Persist workspaces and findings in PostgreSQL/SQLite.
2. Add signed advisory-feed ingestion, timestamps and provenance.
3. Parse lockfiles with full transitive parent-child edges.
4. Add CPE/PURL normalization and validated CycloneDX CBOM output.
5. Add source repository and container image scanning.
6. Add reachability analysis and exploit intelligence.
7. Add role-based access, audit logs and multi-tenant separation.
