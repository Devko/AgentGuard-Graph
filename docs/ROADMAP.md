# AgentGuard Graph Roadmap

AgentGuard Graph is **1.0 stable for the local-first evidence analyzer baseline**.

## Current Status

- v0.1 functional acceptance: **complete**
- v0.1 safety acceptance: **complete**
- v0.1 test acceptance: **complete**
- v1.0 readiness: **complete for the stable local-first baseline**

The stable baseline ingests local evidence packs, builds an Agent Security Graph, reports evidence-calibrated attack paths, surfaces visibility gaps, and writes JSON, Markdown, and self-contained HTML reports. It does not perform live discovery, runtime enforcement, telemetry upload, or breach confirmation.

## 1.0 Closure Artifacts

- Product readiness: `docs/V1_READINESS.md`
- Fixture review: `docs/FIXTURE_REVIEW_NOTES.md`
- Migration guidance: `docs/MIGRATION_0_1_TO_1_0.md`
- Release provenance: `docs/RELEASE_PROVENANCE.md`
- Frozen schema manifest: `schemas/v1/manifest.json`
- Evidence producer contract: `docs/EVIDENCE_PRODUCER_CONTRACT.md`
- Framework support: `docs/AGENT_FRAMEWORK_SUPPORT.md`
- Release checklist: `docs/RELEASE_CHECKLIST.md`

These artifacts close the v1 schema freeze, fixture review, migration, and provenance work.

## Stable Product Surface

- Python 3.10+ package.
- Standard-library-only scanner runtime.
- CLI commands: `scan`, `inventory`, `explain`, `compare`, `portfolio`, `validate`, `init`, `collect`, `doctor`, and `demo`.
- Evidence parsers for agents, MCP tools, OpenAPI JSON, identities, data catalog, approval policy, OPA/Rego and Cedar policy evaluation evidence, JSONL runtime events, common runtime JSON exports, and common data classification exports.
- Offline collectors for local MCP configs, Claude/Cursor-style MCP configs, Microsoft 365 Copilot declarative agent packages, OpenClaw JSON, LangChain/custom manifests, LangGraph config, static code-first framework scans, OpenAPI JSON, common identity/admin exports, data catalog/DLP/sensitivity-label/table classification exports, OPA/Rego and Cedar policy evidence, and runtime exports from tracing stores, approval brokers, MCP hosts, CI systems, and cloud audit logs.
- `doctor` checks for missing exports, likely secrets, persona-specific repair views, machine-readable collection plans, and framework onboarding checklists before handoff.
- Reports include IAM binding coverage, unused identity and permission reporting, and target-specific least-privilege suggestions.
- Attack-path rules for untrusted input, sensitive data, external sends, dangerous tools, financial actions, production changes, persistent memory, IAM gaps, and MCP dangerous tool exposure.
- Offline execution-layer controls analysis for generic tools, prompt-based security boundaries, missing approval, sandbox, egress, secret-denylist, scoped-identity, DLP, change-ticket, amount-threshold, audit controls, and prioritized offline remediation roadmap items.
- Graph nodes and edges with source, confidence, evidence layer, unknowns, visibility gaps, and recommended next evidence.
- Findings and attack paths with stable ids, graph references, evidence quality, path state, runtime observation, runtime event-quality diagnostics, policy analysis, privacy analysis, accepted-risk status, review decisions, remediation, controls, validation steps, and capped public scores.
- JSON, Markdown, and self-contained HTML outputs with no external report assets.

## Persona Feature Review

| Persona | Jobs to be done | Current support | Support level | Next improvement |
| --- | --- | --- | --- | --- |
| Agent developer | Produce a complete evidence pack, fix missing references, and understand which export is needed next. | `collect`, `doctor`, project discovery, framework checklists, secret detection, machine-readable collection plans, validation, explicit bindings, and precise repair text. | Strong for CLI users and local projects. | Add generated evidence patch suggestions for common missing fields and stale references. |
| Platform / agent runtime team | Normalize framework, tool, runtime, and approval evidence across different agent stacks. | Importers cover MCP, OpenAPI, Microsoft 365 Copilot, OpenClaw, LangChain/custom manifests, LangGraph config, static framework scans, runtime JSONL, tracing-store exports, approval broker exports, MCP host logs, CI logs, and cloud audit logs. | Strong for local export files; moderate for hosted platform operations. | Add more hosted export adapters and keep them local-file based before considering direct API connections. |
| IAM / cloud admin | Prove which identity and permission grants are needed by each tool. | Identity/admin importers, explicit/inferred/ambiguous binding coverage, unused identity and permission reporting, and target-specific least-privilege suggestions for major SaaS, cloud, and platform targets. | Strong for local evidence review. | Add entitlement diff support against exported current-state and desired-state permission snapshots. |
| AppSec reviewer | Review one evidence pack, explain findings, compare reports, and judge evidence quality. | `doctor`, `validate`, `scan`, `inventory`, `explain`, `compare`, HTML/Markdown/JSON reports, calibrated attack paths, review decisions, accepted-risk status, visibility gaps, path state, runtime observation, policy analysis, privacy analysis, evidence-manifest status, and owner-routed remediation guidance. | Strong for single-pack review and report comparison. | Add reviewer attestation fields and review package export. |
| CISO / security program owner | See portfolio risk, blockers, exceptions, and trend direction across many agents. | `portfolio` rolls up saved reports by owner, environment, business unit, severity, path state, visibility gaps, accepted-risk status, evidence-manifest status, remediation action priority, and writes a self-contained filterable HTML dashboard. | Moderate. | Add trend cards and risk aging once repeated review lifecycle data is available. |
| Governance / compliance owner | Reopen a review later and prove what evidence, decision, and exception were reviewed. | Stable schemas, release provenance, evidence producer contract, evidence manifests, review decisions, accepted-risk metadata, evidence guide, and local-only reports. | Moderate. | Add reviewer attestation, control mapping, exception lifecycle, and repeated-review audit trail. |
| SRE / runtime owner | Provide existing operational logs and understand whether runtime evidence is trustworthy. | JSONL runtime events and common JSON exports are normalized into runtime reconstruction, observed path states, allowed/blocked events, session diagnostics, and event-quality scoring. | Strong for local runtime evidence imports. | Add optional adapters for common observability export bundles and documented timestamp/session normalization recipes. |
| Data / privacy owner | Determine which agent paths touch regulated data and which classifications are missing. | Data catalog, DLP, sensitivity-label, and table/object classification importers; privacy filters for customer PII, employee data, credentials, payment data, source code, and regulated records; memory retention details with owner, retention period, deletion policy, data classes, and source evidence. | Strong for local privacy evidence review. | Add lineage import support from exported catalog snapshots and make classification gaps owner-routable. |
| Business owner / executive reader | Understand top risks, affected business units, blocking owners, and remediation progress without reading raw evidence. | Review brief, top findings, high-priority gaps, HTML report summary, and filterable HTML portfolio rollup. | Moderate. | Add risk aging, exception status, and owner progress rollups. |
| Security tester / red team | Build reproducible evidence for known agent risk scenarios without executing tools or prompts. | Stable attack-path ids, `explain`, calibrated path states, and runtime evidence ingestion support controlled test data. | Basic. | Add scenario templates, synthetic runtime evidence generation, and a replay-safe validation harness. |

Review summary:

- The core scanner is mature for offline evidence review and report generation.
- The strongest personas are agent developers, IAM admins, AppSec reviewers, runtime owners, and privacy reviewers when they can provide local exports.
- The weakest product areas are governance closure, remediation lifecycle, trend analysis, and tester workflow.
- Direct live API discovery remains intentionally outside the stable baseline; near-term work should improve export-based adapters before adding connected integrations.

## Product Next Steps

These items extend the stable baseline without changing the local-first scan contract. Completed maturity initiatives are kept as closed capabilities; active roadmap items are the next product improvements.

### Recently Closed Capabilities

- Evidence onboarding repair loop: `doctor --write-plan`, persona views, precise repair text, secret detection, and framework checklists.
- IAM and binding maturity: explicit/inferred/ambiguous bindings, unused grants, and target-specific least-privilege suggestions.
- Runtime evidence adapters: common JSON importers, session diagnostics, and event-quality scoring.
- Data and privacy evidence: data catalog, DLP, sensitivity-label, table/object classification, memory retention, and privacy filters.
- Policy-as-code evidence: OPA/Rego and Cedar source and decision import, normalized control rules, policy-rule risk analysis for broad allows, shadowed rules, unmatched rules, and ineffective controls, and report `policy_analysis`.
- Offline execution-layer review: generic-tool findings, recursive review-grade selector-field checks, policy/control coverage gaps, prompt-boundary findings, control coverage scoring, remediation roadmap items, and report `offline_control_analysis`.
- Evidence manifest attestation: `collect` writes `evidence-manifest.json`, and `doctor` reports present, changed, missing, and unmanifested evidence files.
- Owner-routed remediation plans: report `remediation_plan` groups offline action rows by owner, target system, and category.
- Report maturity compare drift: `compare` summarizes evidence-manifest status/count drift and remediation-plan action, priority, owner, system, and category drift.
- Portfolio review and diffing: report/evidence-pack `compare`, saved-report `portfolio`, accepted-risk rollups, evidence-manifest status/drift rollups, and remediation owner/category/system queues.
- HTML portfolio dashboard: `portfolio --html` writes a self-contained local dashboard with filters for owner, business unit, environment, severity, path state, risk status, and visibility-gap priority/type plus manifest and remediation status tables.

### P1: Evidence Manifest Review Attestation

Target personas: AppSec reviewer, governance owner, compliance owner, release operator.

- Add producer notes and reviewer attestation fields without storing evidence contents or secrets.

Acceptance signal: a reviewer can archive an evidence pack and later prove exactly which files were reviewed.

### P1: Remediation Workflow Lifecycle

Target personas: AppSec reviewer, platform team, IAM admin, data owner, business owner.

- Add `next_owner`, `blocking_owner`, and `remediation_status` fields to report-level review summaries.
- Add remediation closure, accepted exception, and pending-evidence lifecycle states.
- Add plan-to-plan drift in portfolio owner queues.
- Keep remediation language evidence-based and avoid claiming a fix was applied unless evidence proves it.

Acceptance signal: each owner can see their queue without reading every finding or raw evidence file.

### P1: Portfolio Trend And Lifecycle Views

Target personas: CISO, AppSec reviewer, governance owner, business owner.

- Add trend and change cards when portfolio inputs include compare results or repeated report labels.
- Add risk aging and remediation status rollups once owner-routed remediation plans exist.

Acceptance signal: AppSec can run a portfolio review meeting from a local HTML file.

### P2: Governance Controls And Exception Workflow

Target personas: governance owner, compliance owner, AppSec reviewer.

- Add optional control mapping fields for internal policy ids and external frameworks without making the scanner depend on one framework.
- Add reviewer decision records with reviewer, owner, reason, expiration, scope, and source evidence.
- Add accepted-risk renewal and closure records.
- Add repeated-review audit trail fields that survive compare and portfolio rollups.

Acceptance signal: a review can be reopened and audited without relying on screenshots, chat history, or tribal knowledge.

### P2: Hosted Export Adapter Coverage

Target personas: platform team, SRE, data owner, privacy owner, AppSec reviewer.

- Add local-file adapters for exported observability bundles from Datadog, New Relic, Honeycomb, and OpenTelemetry collectors.
- Add exported data catalog and lineage snapshot adapters for Purview, Collibra, DataHub, and similar systems.
- Add exported hosted agent platform package adapters where vendors provide stable local bundles.
- Document the minimum required fields for each adapter so owners know when an export is too lossy.

Acceptance signal: runtime, platform, and privacy owners can use common vendor exports without custom normalization scripts.

### P3: Security Tester Workflow

Target personas: security tester, red team, AppSec reviewer.

- Add scenario templates for common agent risk patterns.
- Add synthetic runtime event generation for controlled validation of detection rules.
- Add a replay-safe harness that validates evidence shape without executing tools or prompts.
- Add expected finding/path assertions for regression-style security tests.

Acceptance signal: testers can create reproducible evidence for a scenario and verify that reports make calibrated claims.

### P3: Scale, Accessibility, And Report Hardening

Target personas: AppSec reviewer, CISO, accessibility reviewer, platform team.

- Add performance fixtures for very large evidence packs and reports.
- Add report-size safeguards for HTML rendering and search indexing.
- Add accessibility checks beyond the current self-contained HTML safety gates.
- Add output-message polish tests for high-volume warning and repair scenarios.

Acceptance signal: large reports remain usable, readable, and accessible under realistic portfolio-scale evidence.

## Stable Contracts

The v1 contract is frozen in `schemas/v1/manifest.json`. Product version is `1.0.0`; evidence and report payloads keep `schema_version: "0.1"` for compatibility.

Stable contracts:

- CLI command names and core purposes.
- JSON report top-level fields in `schemas/findings.schema.json`.
- Evidence schema files under `schemas/`.
- Rule id vocabulary for implemented attack-path families.
- Evidence quality, path state, runtime observation, review decision, visibility gap priority, scoring dimension, and tier vocabularies.
- Local-first safety boundary: no live crawling, no tool execution, no telemetry upload, no runtime enforcement claim.

## Milestones

### v0.1.0 Alpha

Closed. Local evidence loading, graph construction, findings, JSON/Markdown/HTML reports, validation, and demos.

### v0.2.0 Adapter And Schema Stabilization

Closed. OpenAPI and identity/admin importers, schema examples, JSON validation output, and schema compatibility warnings.

### v0.3.0 Runtime Evidence

Closed. Reports separate static, supported, partial observation, full observation, allowed, blocked, and unknown path states.

### v0.4.0 Graph And Report Fidelity

Closed. Stable graph vocabulary, path subgraphs, metadata-driven HTML rendering, controls, observed events, and blockers.

### v0.5.0 Policy And Control Model

Closed for the built-in matcher. Approval/control reasoning includes matched controls, missing controls, policy blocked actions, policy snippets, and validation steps.

### v0.6.0 Evidence Producers

Closed for offline importer coverage. Fixtures cover common local config, framework, OpenAPI, and admin export shapes.

### v0.7.0 Release Readiness

Closed. Gates cover compile, unit tests, coverage, package build, offline demo, HTML safety, and generated artifact hygiene.

### v0.8.0 Report Contract And UX

Closed. Report schema, stable ids, operational fields, Markdown escaping, HTML escaping, filters, and self-contained assets are part of the v1 baseline.

### v0.9.0 Release Candidate

Closed. Fixture review notes, schema freeze manifest, migration guidance, score calibration, and CLI/report contract docs are recorded.

### v1.0.0 Stable Local-First Agent Security Graph

Closed for the defined baseline. Use `docs/RELEASE_CHECKLIST.md` before publishing a package or tag.

## Future Backlog

Lower-priority extensions:

- optional MCP proxy, shell wrapper, or approval broker in a separate enforcement track
- direct API connectors after export-based adapters prove stable and useful
- future evidence schema version for breaking input changes

## Current Quality Gate Snapshot

Last recorded local gates:

- `python -m compileall -q src tests`: passing.
- `python -m unittest discover -s tests -v`: passing.
- `coverage report -m --fail-under=85`: 92% total coverage.
- `PYTHONPATH=src python -m agentguard_graph.cli demo`: writes JSON, Markdown, HTML, and inventory outputs.
- `python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist`: package wheel builds locally.
