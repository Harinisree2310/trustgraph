# TrustGraph 2.0 — Architecture and Technical Scope

## End-to-end flow

```text
Dependency manifests / lockfiles / CycloneDX SBOM
                     |
                     v
          Ingestion and normalization
                     |
                     v
       Component inventory + ownership metadata
                     |
          +----------+-----------+
          |                      |
          v                      v
   Advisory intelligence    Dependency relationships
   - OSV.dev live query     - package parent/child edges
   - synthetic demo feed    - application membership
          |                      |
          +----------+-----------+
                     |
                     v
          Finding / incident correlation
                     |
                     v
       Business impact and blast-radius engine
       - matched package records
       - potentially dependent components
       - affected applications
       - business service criticality
       - internet exposure
                     |
                     v
          Explainable risk prioritization
                     |
                     v
       Response plan and remediation tracking
```

## Incident analysis API

### `POST /api/incidents/analyze`

Example request:

```json
{
  "package": "log4j-core",
  "ecosystem": "Maven",
  "severity": "Critical",
  "cvss": 9.8,
  "advisory_id": "TG-SCENARIO-001",
  "fixed_version": "2.17.1",
  "source_type": "simulated_demo"
}
```

The response includes incident context, matching inventory records, potentially dependent components reached through declared dependency edges, affected application and business-service groups, blast-radius counts, scoring factors, reachability and compromise-verification status, and an ordered remediation plan.

### `GET /api/incidents/demo`
Runs the deterministic `log4j-core` scenario. It is explicitly marked `simulated_scenario`; it is not a real compromise alert.

## Risk scoring model

```text
score = min(100,
    severity_weight
  + (CVSS × 2.5)
  + max_affected_service_context
  + direct_presence_bonus
  + additional_application_blast_radius_bonus
)
```

Weights are explicit in `backend/app.py`. The score is not a probability of exploitation, expected financial loss, or proof of reachability. It makes triage factors inspectable and repeatable.

## Evidence levels

| Evidence | What it supports | What it does not prove |
|---|---|---|
| Manifest/SBOM component record | Package/version appears in supplied inventory | Package is deployed or executed |
| Declared dependency edge | A manifest declares a relationship | Vulnerable function is reachable |
| OSV.dev advisory | An upstream vulnerability record matches package/version | A specific organization is compromised |
| Application/business metadata | Potential business context for an inventory record | Actual production ownership unless validated |
| Incident report | A reported event to investigate | Confirmed malicious activity |

## Current limitations and next engineering steps

1. Persist inventories, incident assessments and actions in a database.
2. Validate CycloneDX versions and preserve PURLs, hashes, licenses and dependency edges.
3. Add provenance and signed advisory-feed ingestion with timestamps.
4. Add source repository, container and artifact scanning.
5. Add call-graph/reachability analysis with explicit confidence and language coverage.
6. Add malicious-package and package-provenance signals from trusted sources.
7. Add authentication, authorization, tenant isolation and audit logging.
8. Build automated tests with known-positive and known-negative package/version cases.
