# Migration From 0.1 To 1.0

AgentGuard Graph 1.0 stabilizes the existing local evidence analyzer. Evidence payloads still use `schema_version: "0.1"`. Valid 0.1 packs do not need to be renamed or rewritten.

## Compatible Inputs

- Evidence files remain `agentguard.json`, `mcp-servers.json`, `identity.json`, `data-catalog.json`, `approval-policy.json`, and `events.jsonl`.
- JSON and JSONL remain the core evidence formats.
- Existing `schema_version: "0.1"` files continue to validate.
- CLI command names remain stable: `scan`, `inventory`, `explain`, `validate`, `init`, `collect`, `doctor`, and `demo`.
- Safety boundaries remain unchanged: no live crawling, no tool execution, no telemetry, and no enforcement claim.

## Stable In 1.0

- JSON report contract recorded in `schemas/v1/manifest.json`.
- Findings and attack paths include evidence quality, path state, runtime observation, accepted-risk status, operational context, remediation, score, and raw points.
- Reports include `review_decision`, `review_brief`, `evidence_guide`, `iam_analysis`, and `runtime_reconstruction`.
- Visibility gaps include priority and affected-finding links.
- Public scores are capped from 0 to 100.
- Markdown and HTML use the same operational terminology as JSON.

## Migration Steps

1. Keep existing evidence on `schema_version: "0.1"`.
2. Run `agentguard-graph validate --json --evidence-dir <evidence-dir>`.
3. Fix structural errors first.
4. Review warnings for missing identity, permission, approval, data classification, owner, environment, and runtime event evidence.
5. Run `agentguard-graph scan --evidence-dir <evidence-dir> --out outputs/agent-risk.json --markdown outputs/agent-risk.md --html outputs/agent-risk.html`.
6. Use `evidence_guide` and `review_decision.required_actions` as the evidence collection checklist.
7. Update downstream consumers to read `review_decision`, `evidence_quality`, `path_state`, `risk_status`, `accepted_risk`, `iam_analysis`, `runtime_observation`, `visibility_gap_priorities`, `score`, and `raw_points`.

## Consumer Notes

Treat unknown fields as forward-compatible additions. Do not infer safety from missing findings, missing runtime observations, or empty optional evidence files.

Stable integration points:

- `findings[].id`
- `findings[].rule_id`
- `attack_paths[].rule_id`
- `findings[].evidence_quality`
- `findings[].path_state`
- `runtime_observation.state`
- `iam_analysis.summary`
- `iam_analysis.binding_coverage`
- `review_decision.decision`
- `visibility_gaps[].priority`

## Breaking Changes

There are no required breaking input changes from 0.1 evidence files to the 1.0 product release. Future breaking evidence changes should use a new schema version and a dedicated migration guide.
