# TrustGraph 2.0 — Judge Demonstration Script

## Story
A security team receives a report that a third-party package may be compromised. The team needs to know whether the package appears in its software inventory, which applications and business services could be affected, why the issue should be prioritized, and what response steps to take.

**Important:** The built-in demo is a simulated scenario using seeded inventory. Do not present it as a real compromise or real CVE alert.

## 3–4 minute walkthrough

1. **Establish the software estate.** Open Overview and show the seeded inventory, findings and application context.
2. **Trigger the incident scenario.** Open Incident analysis and select Run compromised-package demo. TrustGraph submits a simulated `log4j-core` incident.
3. **Explain the blast radius.** Show matched package records, potentially impacted components, affected applications and business services. The result is derived from supplied inventory records and declared dependency edges, not runtime execution traces.
4. **Explain prioritization.** Walk through reported severity, CVSS, highest affected-service criticality/exposure, direct package presence and additional application blast radius. This is a transparent triage score, not an exploit probability.
5. **Show the response plan.** Walk through validation, containment, verified patched-version selection, rebuild/testing, downstream review and closure verification.
6. **Separate demo from live intelligence.** If backend internet access is available, run the OSV.dev live check from Overview. OSV vulnerability records are separate from the synthetic demo incident.

## Suggested judge-facing pitch
“Most tools tell a security team that a dependency has a vulnerability. TrustGraph helps answer the next operational question: where does this component appear in our software estate, which business services could be affected, why should we prioritize it, and what should our response sequence be? We connect component evidence to application context and an explainable remediation workflow.”

## Questions to prepare for

- **Does this prove compromise?** No. It analyzes a reported or simulated incident against inventory evidence.
- **Does it prove exploitability?** No. Runtime reachability and exploit preconditions are not assessed in this MVP.
- **Are all advisories live?** No. TG-DEMO records are synthetic; OSV.dev results are queried separately.
- **How accurate is the blast radius?** It depends on completeness and correctness of supplied manifests, dependency edges and ownership metadata.
- **What is next?** Persistent storage, validated SBOM parsing, signed intelligence sources, artifact scanning and reachability analysis.
