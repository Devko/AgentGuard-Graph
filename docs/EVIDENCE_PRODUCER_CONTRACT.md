# Evidence Producer Contract

Evidence producers write local files for AgentGuard Graph. They do not give the scanner live credentials, tenant access, repository access, MCP access, or cloud access.

## Files

An evidence pack may contain:

```text
agentguard.json
mcp-servers.json
identity.json
data-catalog.json
approval-policy.json
events.jsonl
openapi/
evidence-manifest.json
```

Each JSON evidence file should use `schema_version: "0.1"`. Newer or older schema versions are validated in compatibility mode and produce warnings.

When `collect` creates a pack, it also writes `evidence-manifest.json`. This attestation file records file paths, SHA-256 hashes, byte sizes, schema versions where available, source kind, tool version, and collection time. It does not include evidence contents. `doctor` validates the manifest and reports changed, missing, and unmanifested files.

Examples live in:

- `schemas/examples/minimal`
- `schemas/examples/typical`
- `schemas/examples/high-fidelity`

## Minimum Evidence

Minimum evidence establishes inventory, not confidence:

- agent id
- tools
- identities
- input sources
- autonomy
- optional `tool_identity_bindings`
- tool ids and known risk tags

Missing identity, permissions, data classification, owner, environment, approval policy, or runtime logs becomes a visibility gap.

## Typical Evidence

Add:

- owner, runtime, environment, and business unit
- approval policy id
- explicit `tool_identity_bindings` when one agent uses multiple identities on the same target
- identity exports with target systems, scopes, permissions, resources, actions, and confidence
- data catalog entries with target systems, data classes, and sensitivity
- memory-store retention detail with owner, retention period, deletion policy, data classes, and source evidence
- approval rules for sensitive reads, external sends, financial actions, production writes, command execution, and memory retention
- runtime events with `agent`, `session_id`, `timestamp`, `tool`, `decision`, `policy`, `identity`, `action_class`, and `data_classes`

## Offline Control Evidence

For high-risk tools, include local approval-policy evidence that proves the intended control posture without giving the scanner live access. Useful rule controls include `approval_required`, `sandbox_control`, `egress_allowlist`, `secret_denylist`, `scoped_identity`, `dlp_redaction`, `change_ticket_required`, `amount_threshold`, and `audit_logging`.

Tool schemas should constrain selector fields such as paths, URLs, customer ids, resource ids, and queries. Prefer typed properties with `required`, bounded `enum` or `pattern` plus length limits where possible, and `additionalProperties: false` for nested selector objects. Weak hints such as only `format: uri`, only `maxLength`, or optional selector fields are still reported as generic tool surfaces for high-risk tools.

Reports expose this review in `offline_control_analysis` and policy-rule review in `policy_analysis.rule_risks`. Treat those sections as reviewer work queues: they identify missing evidence, broad allows, conflicting decisions, shadowed rules, unmatched dead rules, ineffective controls, generic tools, and prompt text that appears to carry security decisions better enforced by policy or permission evidence.

## High-Fidelity Evidence

Preserve:

- stable event ids
- session ids across a full task flow
- ordered tool-call events
- allowed and blocked attempts
- policy ids or rule names
- identity used for each tool call
- data classes reached by the action
- source file or export name for traceability

This lets reports distinguish `possible`, `supported`, `observed_partial`, `observed_full`, `observed_allowed`, and `observed_blocked`.

## Redaction

Do not include secrets, tokens, raw customer content, raw prompts, or full record payloads unless a local reviewer has explicitly approved that scope.

Keep review metadata:

- service account or app id, not secret value
- OAuth scope names, not tokens
- object, field, and classification names, not record contents
- event ids and session ids, not full prompts
- policy ids and decisions, not policy engine internals

Run `agentguard-graph doctor --evidence-dir <dir> --profile developer --write-plan` before packaging. It detects likely secrets and writes `collection-plan.json` with the next export, target file, owner, reason, repair text, and command. Use `--profile iam-admin`, `--profile data-owner`, or `--profile security-reviewer` to route the remaining actions.

## Microsoft 365 Copilot Agents

Provide local package artifacts:

- app package directory or zip with `manifest.json`
- referenced declarative agent manifest, usually `declarativeAgent.json`
- referenced API plugin or remote MCP plugin manifests
- local JSON OpenAPI documents referenced by plugin runtimes
- admin exports for Microsoft 365, Entra, Dataverse, connector, DLP, sensitivity-label, and audit permissions when `doctor` reports gaps

The collector normalizes Copilot capabilities, API plugin functions, and remote MCP tool descriptions. It does not fetch remote OpenAPI URLs, call Microsoft Graph, call Dataverse, connect to MCP servers, or retrieve tenant data.

## Runtime Exports

Prefer existing JSON exports from the systems that already observe the agent:

- agent tracing stores with spans, traces, runs, or events
- approval brokers with requests or decisions
- MCP hosts with tool calls or server requests
- CI systems with workflow runs, jobs, or steps
- cloud audit logs such as AWS CloudTrail, Google Cloud audit logs, or Azure activity logs

Use:

```bash
agentguard-graph collect \
  --out agent-evidence/ \
  --agent-trace-export agent-traces.json \
  --approval-broker-export approvals.json \
  --mcp-host-log mcp-host-log.json \
  --ci-system-log ci-runs.json \
  --cloud-audit-log cloud-audit-log.json
```

Importers normalize these records into `events.jsonl`. Reports separate clean runtime evidence from low-correlation traces and emit repair text for missing `session_id`, missing `agent`, missing `tool`, missing or invalid timestamps, and inconsistent session timestamps.

## Data And Privacy Exports

Prefer existing privacy and classification exports:

- data catalogs with assets, datasets, tables, objects, entities, or resources
- DLP findings with resources, fields, info types, likelihood, and labels
- sensitivity-label exports from Microsoft Purview, MIP, or equivalent systems
- table, column, object, or field classification exports

Use:

```bash
agentguard-graph collect \
  --out agent-evidence/ \
  --data-catalog-export purview-assets.json \
  --dlp-export dlp-findings.json \
  --sensitivity-label-export sensitivity-labels.json \
  --table-classification-export table-classifications.json
```

Importers normalize these records into `data-catalog.json`. Reports show data exposures by finding, classification gaps, memory retention ownership, retention period, deletion policy, source evidence, and filters for customer PII, employee data, credentials, payment data, source code, and regulated records.

## Policy Evaluation Exports

Prefer local policy-as-code outputs that include the policy decision and the authorization input:

- OPA decision logs or `opa eval --format=json` output
- Rego source files with simple `allow`, `deny`, or `approval_required` rules
- Cedar policy source files with `permit` or `forbid` policies
- Cedar authorization result JSON with decision, request, and diagnostics

Use:

```bash
agentguard-graph collect \
  --out agent-evidence/ \
  --opa-eval opa-decision-log.json \
  --rego-policy policy.rego \
  --cedar-policy policy.cedar \
  --cedar-eval cedar-authorize.json
```

Concrete evaluations should include `agent`, `tool` or `action`, `target_system`, `environment`, and `data_classes`. Importers normalize these records into `approval-policy.json` and preserve all evaluations in report `policy_analysis`. Evaluations without concrete match context are reported as gaps, not broad rules.

## Permission Exports

Prefer native admin exports in JSON form. Supported targets are listed in [docs/PERMISSION_TARGETS.md](PERMISSION_TARGETS.md): GitHub, Google Workspace, Slack, Salesforce, AWS IAM, Kubernetes RBAC, Microsoft 365 / Microsoft Graph, Azure RBAC, Google Cloud IAM, Dataverse, Power Platform, Okta, Jira, Confluence, Zendesk, ServiceNow, Snowflake, Databricks, Stripe, and NetSuite.

Exports should preserve identity ids, role names, resources, scopes, actions, grants, object/table names, and confidence where available. Importers normalize records into `identity.json` permissions and emit warnings for malformed rows.

## Code-First Frameworks

Provide source and config artifacts, not executable access:

- project path passed with `--framework-code`
- dependency files such as `pyproject.toml`, `requirements.txt`, `uv.lock`, or `poetry.lock`
- static agent construction and tool wiring code
- CrewAI `config/agents.yaml`
- MCP descriptors, OpenAPI JSON, or explicit tool manifests for dynamic tools
- identity, permission, approval, data catalog, and runtime exports from the deployed environment

The framework collector is static. It recognizes LangChain/LangGraph, AutoGen, LlamaIndex, CrewAI, Agno, Semantic Kernel, Microsoft Agent Framework, OpenAI Agents SDK, Google ADK, Haystack, Pydantic AI, and CAMEL. It does not import modules, execute decorators, call framework CLIs, resolve remote tools, or infer production IAM.

## Compatibility

- `0.1` is the supported evidence schema version.
- Older and newer schema versions warn and validate in compatibility mode.
- Non-numeric schema versions warn.
- JSON Schemas in `schemas/` are external validator contracts.
- The built-in CLI validator remains dependency-free.
