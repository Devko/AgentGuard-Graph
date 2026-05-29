# AgentGuard Graph 1.0 Readiness

This document records the stable v1 baseline. Release operations such as tag signing, package publication, and partner fixture expansion are handled separately.

## Decision

AgentGuard Graph is ready as the **1.0 stable local-first baseline**.

The product is an offline evidence analyzer. It is not a live scanner, policy enforcement layer, MCP proxy, telemetry service, or exploitability engine. A user supplies local evidence packs and receives JSON, Markdown, and self-contained HTML reports that separate possible, supported, observed, blocked, and unknown paths.

## Stable Surface

- CLI commands: `scan`, `inventory`, `explain`, `compare`, `portfolio`, `validate`, `init`, `collect`, `doctor`, and `demo`.
- `doctor` prioritizes missing exports, writes collection plans, supports persona repair views, and blocks packaging when likely secrets are present.
- `collect` writes an offline `evidence-manifest.json`, and `doctor` reports manifest drift when files are changed, missing, or unmanifested.
- Scanner runtime uses the Python standard library only.
- Evidence inputs are JSON, JSONL, and local policy source files for Rego or Cedar.
- `collect` imports data classification JSON exports from data catalogs, DLP scanners, sensitivity-label systems, and table/object classification reports into `data-catalog.json`.
- `collect` imports OPA/Rego and Cedar policy source or evaluation JSON into `approval-policy.json`.
- `collect` imports runtime JSON exports from tracing stores, approval brokers, MCP hosts, CI systems, and cloud audit logs into `events.jsonl`.
- Malformed or unsupported inputs produce explicit errors or warnings.
- Reports include review decisions, evidence quality, path state, runtime observation, runtime event-quality scoring, runtime correlation diagnostics, offline control analysis, policy rule-risk analysis, owner-routed remediation plans, privacy analysis, accepted-risk status, IAM binding coverage, unused grants, least-privilege suggestions, visibility gaps, remediation, policy snippets, runtime reconstruction, evidence collection guidance, evidence-manifest and remediation compare drift, and saved-report portfolio rollups.
- HTML reports are self-contained and escape untrusted evidence strings.
- Public scores are capped at 100; `raw_points` remains available for diagnostics.
- Missing identity, permission, approval, data classification, owner, environment, or runtime evidence is reported as a visibility gap.

## Frozen Contracts

The v1 freeze is recorded in [../schemas/v1/manifest.json](../schemas/v1/manifest.json). Product version is `1.0.0`; evidence and report payloads keep `schema_version: "0.1"` until a future breaking evidence-format change.

The freeze covers:

- evidence schemas in `schemas/*.schema.json`
- report schema in `schemas/findings.schema.json`
- evidence manifest fields
- rule ids for current attack-path families
- evidence quality and path state vocabulary
- offline control analysis fields
- policy analysis fields, policy rule-risk fields, and policy evaluation import flags
- remediation plan fields
- compare drift fields for evidence manifests and remediation plans
- portfolio rollup fields for evidence manifests and remediation plans
- privacy analysis fields and data-category filter labels
- runtime event-quality fields and correlation diagnostic types
- visibility gap priority vocabulary
- review decision vocabulary
- score and tier semantics
- no-network, no-telemetry, no-enforcement boundaries

## Verification Baseline

```bash
python -m compileall -q src tests
python -m unittest discover -s tests -v
coverage run --source=src/agentguard_graph -m unittest discover -s tests
coverage report -m --fail-under=85
PYTHONPATH=src python -m agentguard_graph.cli demo
```

Package build gate:

```bash
python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
```

## Non-Goals

- live cloud, SaaS, repository, or identity crawling
- MCP tool execution
- OpenAPI operation execution
- runtime policy enforcement
- telemetry upload
- exploitability or breach confirmation claims
- treating absent runtime events as proof of safety

## Release Operations

Use [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) before publishing a package or tag. Those checks are release hygiene, not open v1 product gaps.
