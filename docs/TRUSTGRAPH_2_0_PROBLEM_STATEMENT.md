# TrustGraph 2.0 — Refined Problem Statement

## Project title
**TrustGraph: Business-Aware Third-Party Software Supply-Chain Risk Intelligence**

## Problem statement
Modern organizations assemble business-critical applications from thousands of third-party and open-source software components. A single vulnerable, compromised, abandoned, or malicious dependency can propagate through direct and transitive relationships into multiple applications and business services. Existing vulnerability lists and package scanners often leave security teams with a fragmented view: they identify a package or advisory, but do not consistently translate that signal into an evidence-backed picture of which internal applications and business operations may be affected, how urgently the organization should respond, and what safe remediation sequence should follow.

Security and engineering teams therefore face three connected questions during a supply-chain incident:

1. **Where is the component?** Which application manifests, lockfiles and software bills of materials contain the reported package and version?
2. **What could it affect?** Which dependent components, applications and business services are connected to those inventory records, and what are their criticality and exposure?
3. **What should happen next?** How should the organization validate the advisory, contain affected releases, select a verified patched version, rebuild, test and confirm remediation?

TrustGraph addresses this gap with an explainable, business-aware workflow that connects component inventory, vulnerability intelligence, dependency relationships, application ownership and remediation guidance.

## Proposed solution
TrustGraph ingests supported dependency manifests and SBOM component records, normalizes package identity and version information, and compares inventory against vulnerability intelligence. When an incident is reported, it performs an inventory-backed impact assessment: matching package records, traversing declared dependency edges where available, grouping potential impact by application and business service, and prioritizing response using transparent severity, CVSS, criticality, exposure and blast-radius factors. It then generates a staged response plan for validation, containment, safe-version selection, rebuild/testing and closure verification.

## Core capabilities
- Software component inventory across supported npm, PyPI and CycloneDX inputs.
- Vulnerability intelligence with source provenance; live OSV.dev results are distinct from deterministic demo data.
- Dependency and application relationship mapping.
- Business-context risk prioritization with visible scoring factors.
- Incident impact analysis and potential blast-radius reporting.
- Actionable remediation workflow and JSON/CSV reporting.
- Clear evidence labels and limitations to prevent unsupported security claims.

## Intended users
- Product security and application security teams.
- Software supply-chain / DevSecOps engineers.
- Security operations and incident-response teams.
- Technology risk owners responsible for business-critical applications.

## Differentiation
TrustGraph's central product proposition is not another flat CVE list. It is the translation layer between a third-party software signal and the organization's business context: **package → dependency relationship → application → business service → prioritized response**. The value is an explainable answer to “what should we investigate and fix first, and why?”

## Expected outcome
Reduce the manual effort required to connect a third-party software incident to internal application ownership and business impact, while giving responders a traceable, prioritized remediation starting point.

## Scope and honesty statement
The current MVP is an inventory-based prototype. It does not independently prove that a package is malicious, that a compromise occurred, or that vulnerable code is reachable or executed at runtime. Dependency relationships are only as complete as the imported manifests and SBOMs. The built-in TG-DEMO advisory catalogue and demo incident are synthetic scenarios, not real CVEs or real compromise alerts. Live OSV.dev checks provide external vulnerability records when the backend has internet access, but OSV is vulnerability intelligence—not a complete supplier-compromise detection feed. Risk scores are prioritization heuristics, not calibrated probabilities. All incident and remediation decisions require validation against authoritative upstream advisories, deployed artifacts and organizational incident-response procedures.
