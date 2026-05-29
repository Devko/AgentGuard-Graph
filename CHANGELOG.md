# Changelog

## Unreleased

- Added `agentguard-graph compare` for saved JSON reports.
- Added direct evidence pack directory inputs to `agentguard-graph compare`.
- Added JSON and Markdown comparison outputs with new, resolved, improved, regressed, changed, and unchanged finding classifications.
- Added visibility-gap deltas to comparison output.
- Added `agentguard-graph portfolio` for multi-report owner, environment, business-unit, severity, path-state, and visibility-gap rollups.
- Added JSON and Markdown portfolio outputs with top findings, top visibility gaps, and review actions.
- Added accepted-risk status and expiration metadata on findings, attack paths, compare output, portfolio output, Markdown, and HTML reports.
- Added `doctor --write-plan`, `doctor --profile`, persona repair views, and framework onboarding checklists for evidence collection.
- Added IAM binding coverage, unused identity and permission reporting, and target-specific least-privilege suggestions in scan reports.
- Added data catalog, DLP, sensitivity-label, and table/object classification importers plus privacy analysis and memory retention detail in reports.
- Added runtime JSON importers for agent traces, approval brokers, MCP host logs, CI logs, and cloud audit logs, plus runtime event-quality diagnostics in reports.
- Added OPA/Rego and Cedar policy evidence importers plus policy evaluation analysis in reports.

## 1.0.0

- Stabilized the local-first evidence analyzer baseline.
- Froze the v1 report contract in `schemas/v1/manifest.json` while retaining `schema_version: "0.1"` for payload compatibility.
- Added `doctor` to prioritize missing exports and detect likely secrets before evidence handoff.
- Added `collect` support for local MCP configs, OpenAPI JSON, Microsoft 365 Copilot declarative agent packages, OpenClaw JSON, LangChain/custom manifests, LangGraph config, static framework scans, and common permission exports.
- Added explicit `tool_identity_bindings` for agents that route different tools through different identities.
- Expanded permission importers across the top enterprise targets listed in `docs/PERMISSION_TARGETS.md`.
- Expanded framework detection across the targets listed in `docs/AGENT_FRAMEWORK_SUPPORT.md`.
- Added evidence quality, path state, runtime observation, review decisions, evidence guide, runtime reconstruction, remediation, policy snippets, and visibility gap priorities to reports.
- Kept JSON, Markdown, and self-contained HTML outputs offline and dependency-free in the scanner runtime.
- Updated samples and demo data, including the multi-agent `demo-enterprise` pack.
- Hardened validation, malformed input handling, output messages, OpenAPI directory handling, and test coverage.

## 0.1.0

- Added local evidence parsing for agents, MCP tools, identities, data catalog, approval policy, and runtime events.
- Added graph construction, attack-path analysis, stable finding/path ids, and `validate --json`.
- Added JSON, Markdown, and self-contained HTML reports.
- Added sample packs, demo command, and development quality gates.
