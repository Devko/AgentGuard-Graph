# End-To-End Workflow

Use this guide to collect local evidence, check whether it is safe to package, validate structure, generate reports, and explain a path. The scan path stays offline and read-only.

## 1. Handoff Model

1. Security asks the agent owner for an AgentGuard evidence bundle.
2. The owner runs `agentguard-graph collect` near the agent code or config.
3. The owner runs `agentguard-graph doctor --evidence-dir agent-evidence/`.
4. The owner adds missing identity, data, approval, and runtime exports where available.
5. The owner runs `doctor` again before sharing the bundle.
6. Security runs `doctor`, `validate`, `inventory`, `scan`, `compare`, `portfolio`, and `explain` with `--evidence-dir` and saved reports.
7. Reviewers record any approved exceptions as `risk_acceptances` with expiration dates, then re-run `scan`, `compare`, or `portfolio`.

The bundle is the audit contract. Do not hand-author evidence when reliable runtime, admin, or build exports exist.

## 2. Covered Workflows

Executable tests cover:

- project collection with `collect --project-dir`
- evidence onboarding with `doctor --project-dir` and `doctor --evidence-dir`
- explicit source collection with MCP, OpenAPI, LangGraph, tools, identities, and input sources
- OpenClaw and LangChain/custom manifest collection
- code-first framework collection through static Python scans
- permission export collection for common identity systems
- OPA/Rego and Cedar policy evaluation import into approval policy evidence
- sample bundles created by `init --sample`
- direct file-path mode for `validate`, `scan`, and `inventory`
- report comparison with `compare`
- portfolio rollup with `portfolio`
- accepted-risk metadata with expiration handling
- offline demo mode

Developer command:

```bash
agentguard-graph collect \
  --out agent-evidence/ \
  --agent-id coding-agent \
  --runtime claude-code-like \
  --environment local \
  --autonomy approval_required \
  --input-source pull_request_comment:untrusted:"External PR comments" \
  --identity github:code-agent \
  --tool-identity-binding github.create_pr=github:code-agent \
  --mcp-config path/to/mcp-config.json \
  --openapi path/to/openapi.json \
  --github-app-export path/to/github-app-permissions.json
```

Project auto-discovery:

```bash
agentguard-graph collect \
  --project-dir . \
  --out agent-evidence/ \
  --input-source pull_request_comment:untrusted:"External PR comments" \
  --identity github:code-agent
```

Security review commands:

```bash
agentguard-graph doctor --evidence-dir agent-evidence/

agentguard-graph validate --json --evidence-dir agent-evidence/

agentguard-graph scan \
  --simple \
  --evidence-dir agent-evidence/ \
  --out outputs/coding-agent/agent-risk.json \
  --markdown outputs/coding-agent/agent-risk.md \
  --html outputs/coding-agent/agent-risk.html
```

Use `--simple` for the first pass with a new team. It keeps the JSON report complete but makes Markdown and HTML focus on what matters, what to fix first, and what evidence to request. Omit it when reviewers want all IAM, policy, privacy, runtime, scoring, and raw-evidence details expanded.

## 3. Collect From Local Sources

`collect --project-dir` looks for:

- MCP configs: `.mcp.json`, `.claude/mcp_servers.json`, `.cursor/mcp.json`
- OpenClaw configs: `openclaw.json`, `.openclaw/openclaw.json`
- custom tool manifests: `agentguard-tools.json`, `langchain-tools.json`, `agent-tools.json`, `tools.json`
- LangGraph config: `langgraph.json`
- Python dependency files that reference supported frameworks
- CrewAI `config/agents.yaml`
- Microsoft 365 Copilot app package files: `appPackage/manifest.json`, `declarativeAgent.json`, `copilot-agent.zip`
- OpenAPI JSON: `openapi.json`, `swagger.json`, `api/openapi.json`, `docs/openapi.json`, `openapi/`, `api-specs/`
- permission exports: GitHub App, OAuth scopes, Salesforce, AWS IAM, Kubernetes RBAC, Microsoft 365, Azure RBAC, GCP IAM, Dataverse, Power Platform, Okta, Jira, Confluence, Zendesk, ServiceNow, Snowflake, Databricks, Stripe, and NetSuite
- policy evaluation evidence: `policy.rego`, `approval-policy.rego`, `opa-eval.json`, `opa-decision-log.json`, `policy.cedar`, `cedar-authorize.json`

Example:

```bash
agentguard-graph collect \
  --project-dir . \
  --out agent-evidence/ \
  --input-source customer_email:untrusted:"Customer-controlled email" \
  --identity salesforce:support-agent-connected-app=oauth_client:salesforce
```

Microsoft 365 Copilot declarative agent package:

```bash
agentguard-graph collect \
  --out agent-evidence/ \
  --copilot-agent appPackage/manifest.json \
  --identity microsoft365:user-delegated=user_delegated:microsoft_365
```

Generated pack:

```text
agent-evidence/
  agentguard.json
  mcp-servers.json
  identity.json
  data-catalog.json
  approval-policy.json
  events.jsonl
  collector-summary.json
  openapi/
```

`collect` reads local files only. It does not start MCP servers, execute code, call cloud APIs, connect to SaaS, fetch remote OpenAPI URLs, or parse YAML OpenAPI.

Run `doctor` before packaging:

```bash
agentguard-graph doctor \
  --evidence-dir agent-evidence/ \
  --profile developer \
  --write-plan agent-evidence/collection-plan.json
```

`doctor` reports `package_ready`, lists prioritized next exports, writes a machine-readable collection plan, and exits `3` when likely secrets are found unless configured otherwise. Each plan action has the export owner, target file, reason, repair text, exact export, and command. Use `--profile iam-admin`, `--profile data-owner`, or `--profile security-reviewer` to show the slice owned by that reviewer.

## 4. Starter Evidence

Create a minimal pack:

```bash
agentguard-graph init --out agent-evidence/
```

Copy a complete sample:

```bash
agentguard-graph init --out agent-evidence/ --sample support-agent
agentguard-graph init --out coding-evidence/ --sample coding-agent
agentguard-graph init --out demo-evidence/ --sample demo-enterprise
```

Edit generated files with exported evidence. Do not include secrets, raw prompts, raw customer records, tokens, private keys, or proprietary descriptors that are not needed for local review.

## 5. Where Inputs Come From

| File | Purpose | Source |
| --- | --- | --- |
| `agentguard.json` | agent inventory, tool wiring, identities, inputs, memory, approval policy | runtime config, deployment manifest, internal catalog, owner review |
| `mcp-servers.json` | static MCP server and tool descriptors | MCP host export, server source, server docs |
| OpenAPI JSON | HTTP API tools | service repo artifact, API gateway export, developer portal download |
| `identity.json` | identities, scopes, permissions, resources | GitHub App, OAuth app, Salesforce, IAM, RBAC, admin exports |
| `data-catalog.json` | data sources and sensitivity | data catalog, CMDB, privacy inventory, owner classification |
| `approval-policy.json` | approval, deny, and control evidence | human review rules, change policy, DLP, allowlists, audit controls, OPA/Rego or Cedar evaluations |
| `events.jsonl` | runtime observations | tool-call logs, approval logs, policy-deny logs, audit trails |

## Quick Recipes For Supported Producers

Use these recipes to turn source evidence into AgentGuard Graph input.

### MCP-Based Tools

Goal: produce `mcp-servers.json` and list each MCP tool under the relevant agent in `agentguard.json`.

1. Read the MCP client or agent-host config.
2. Record server id, display name, transport, and auth mode.
3. Export or copy tool descriptors from a trusted source.
4. Preserve tool name, description, input schema, target system, and known risk tags.
5. Save the normalized file as `agent-evidence/mcp-servers.json`.
6. Add the same tool names to `agents[].tools`.

If risk tags are unknown, omit them. AgentGuard Graph will infer weak tags. Do not invent high-confidence tags without evidence.

Example:

```json
{
  "mcpServers": {
    "workspace": {
      "command": "mcp-shell",
      "tools": [
        {
          "name": "shell.run",
          "description": "Run shell commands in the workspace",
          "target_system": "local_workspace"
        }
      ]
    }
  }
}
```

### OpenAPI-Backed Tools

Goal: provide OpenAPI JSON with `--openapi`.

Sources:

- `openapi.json` or `swagger.json` from the service repository
- API gateway export
- internal developer portal download
- framework-generated JSON from a local development instance

Keep the file as JSON. Convert YAML outside AgentGuard Graph.

Example scan:

```bash
agentguard-graph scan \
  --agents agent-evidence/agentguard.json \
  --openapi api-specs/openapi.json \
  --identity agent-evidence/identity.json \
  --data-catalog agent-evidence/data-catalog.json \
  --approval-policy agent-evidence/approval-policy.json \
  --out outputs/my-agent/agent-risk.json
```

OpenAPI operations become tools. Risk tags are inferred from method, path, operation id, description, schema hints, and security scopes.

### Custom, LangChain, OpenClaw, Claude-Code-Like, And Cloud Agent Platforms

Goal: produce `agentguard.json`, then add tool, identity, data, policy, and event evidence.

Record one `agents[]` object per deployed agent:

- stable id
- runtime
- owner and environment
- autonomy
- tools
- identities
- input sources
- memory stores
- approval policy id
- optional `tool_identity_bindings`

Example manifest accepted by `collect`:

```json
{
  "tools": [
    {
      "name": "github.create_pr",
      "description": "Create a GitHub pull request",
      "risk_tags": ["repository_write"],
      "target_system": "github"
    }
  ],
  "agents": [
    {
      "id": "coding-agent",
      "runtime": "langchain",
      "tools": ["github.create_pr"],
      "identities": ["github:code-agent"],
      "input_sources": ["pull_request_comment"],
      "tool_identity_bindings": [
        {"tool": "github.create_pr", "identity": "github:code-agent"}
      ]
    }
  ],
  "input_sources": [
    {
      "id": "pull_request_comment",
      "trust": "untrusted",
      "description": "External pull request comments"
    }
  ]
}
```

Run:

```bash
agentguard-graph collect --project-dir . --out agent-evidence/
```

For code-first Python frameworks, `collect --framework-code PATH` scans source without importing project modules. It recognizes LangChain/LangGraph, Microsoft AutoGen, LlamaIndex, CrewAI, Agno, Semantic Kernel, Microsoft Agent Framework, OpenAI Agents SDK, Google ADK, Haystack, Pydantic AI, and CAMEL.

### Identity Systems

Goal: produce `identity.json`.

Start with the runtime identity used by each agent: service account, OAuth app, GitHub App, connected app, IAM role, Kubernetes service account, or delegated user identity.

Normalize permissions into:

- `resource`
- `actions`
- `data_classes`
- `confidence`

Empty permission lists are valid when only the identity id and target system are known. They produce IAM visibility gaps.

Use local exports where possible:

```bash
agentguard-graph collect \
  --project-dir . \
  --out agent-evidence/ \
  --github-app-export github-app-permissions.json \
  --oauth-scopes-export slack-oauth-scopes.json \
  --salesforce-permissions-export salesforce-permissions.json \
  --aws-iam-policy aws-iam-policy.json \
  --kubernetes-rbac kubernetes-rbac.json
```

#### GitHub App Permissions

Use a sanitized GitHub App permission export. Do not include private keys or webhook secrets.

```json
{
  "identity_id": "github:code-agent",
  "permissions": {
    "contents": "write",
    "pull_requests": "write",
    "metadata": "read"
  }
}
```

```bash
agentguard-graph collect \
  --out agent-evidence/ \
  --github-app-export github-app-permissions.json
```

#### Slack Or Google OAuth Scopes

Use an app/admin console scope export. Do not include access tokens, refresh tokens, client secrets, or signing secrets.

```json
{
  "identity_id": "slack:support-agent",
  "target_system": "slack",
  "scopes": ["chat:write", "users:read", "files:read"]
}
```

```bash
agentguard-graph collect \
  --out agent-evidence/ \
  --oauth-scopes-export slack-oauth-scopes.json
```

For Google Workspace, use `target_system: "google_workspace"` and include Gmail or Drive scopes from the app registration export.

#### Salesforce Object Permissions

Use a connected app, permission set, profile export, or sanitized permission report.

```json
{
  "identity_id": "salesforce:support-agent-connected-app",
  "objectPermissions": [
    {"object": "Contact", "permissionsRead": true},
    {"object": "Case", "permissionsRead": true, "permissionsEdit": true}
  ]
}
```

```bash
agentguard-graph collect \
  --out agent-evidence/ \
  --salesforce-permissions-export salesforce-permissions.json
```

#### AWS IAM Policy

Use a policy JSON export or sanitized infrastructure-as-code output. Do not include access keys.

```json
{
  "identity_id": "aws:agent-role",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue", "cloudformation:UpdateStack"],
      "Resource": "*"
    }
  ]
}
```

```bash
agentguard-graph collect \
  --out agent-evidence/ \
  --aws-iam-policy aws-iam-policy.json
```

#### Kubernetes RBAC

Use a sanitized Role or ClusterRole JSON export. Do not include service-account tokens.

```json
{
  "kind": "ClusterRole",
  "metadata": {"name": "agent-runner"},
  "rules": [
    {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]},
    {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["patch"]}
  ]
}
```

```bash
agentguard-graph collect \
  --out agent-evidence/ \
  --kubernetes-rbac kubernetes-rbac.json
```

### Data And Privacy Classification

Goal: produce `data-catalog.json`.

Prefer the classification systems data owners already operate. `collect` accepts common JSON exports from data catalogs, DLP scanners, sensitivity-label systems, and table/object classification reports:

```bash
agentguard-graph collect \
  --out agent-evidence/ \
  --data-catalog-export purview-assets.json \
  --dlp-export dlp-findings.json \
  --sensitivity-label-export sensitivity-labels.json \
  --table-classification-export table-classifications.json
```

Useful fields are `id`, `name`, `target_system`, `owner`, `data_classes`, `sensitivity`, `classification_labels`, `fields`, and `source_evidence`. The importer also maps common labels such as PII, email, payment, source code, and secrets into AgentGuard data classes.

For persistent memory stores in `agentguard.json`, include retention detail:

```json
{
  "id": "support-vector-store",
  "persistence": "persistent",
  "owner": "support-data",
  "retention_policy": "ticket-summary-retention",
  "retention_period": "90 days",
  "deletion_policy": "delete on case erasure request",
  "data_classes": ["support_history", "customer_pii"],
  "source_evidence": ["privacy-inventory-2026-05"]
}
```

Reports include a Data And Privacy Evidence section and HTML filters for customer PII, employee data, credentials, payment data, source code, and regulated records.

### Policy-As-Code Evaluation

Goal: produce `approval-policy.json` with reviewable policy decisions.

Use local policy source or evaluation JSON. AgentGuard Graph does not execute OPA or Cedar; it imports evidence that already exists on disk:

```bash
agentguard-graph collect \
  --out agent-evidence/ \
  --opa-eval opa-decision-log.json \
  --rego-policy policy.rego \
  --cedar-policy policy.cedar \
  --cedar-eval cedar-authorize.json
```

Concrete evaluations should include `agent`, `tool` or `action`, `target_system`, `environment`, and `data_classes`. Those become approval-policy rules. Ambiguous evaluations remain in `policy_analysis` as repairable gaps.

### Runtime Logs And Audit Trails

Goal: produce `events.jsonl`.

Export tool calls, approvals, denies, memory events, external sends, or audit events from the runtime you operate. If you already have JSON exports, pass them directly to `collect`:

```bash
agentguard-graph collect \
  --out agent-evidence/ \
  --agent-trace-export agent-traces.json \
  --approval-broker-export approvals.json \
  --mcp-host-log mcp-host-log.json \
  --ci-system-log ci-runs.json \
  --cloud-audit-log cloud-audit-log.json
```

Accepted export shapes include JSON arrays and common wrappers such as `events`, `spans`, `traces`, `runs`, `approvals`, `tool_calls`, `workflow_runs`, `jobs`, `Records`, `protoPayloads`, and `value`. The collector writes normalized rows to `events.jsonl`.

If you write `events.jsonl` yourself, each line must be one JSON object.

Preferred fields:

- `event_type`
- `timestamp`
- `agent`
- `session_id`
- `input_source`
- `tool`
- `action_class`
- `data_classes`
- `identity`
- `decision`
- `policy`
- `confidence`

Runtime events raise confidence for observed behavior. They do not prove future behavior is safe.

Scan reports score runtime event quality. Diagnostics list missing `session_id`, missing `agent`, missing `tool`, missing or invalid timestamps, and inconsistent timestamps within the same session, with repair text for the next export.

## 6. Generate Each JSON Input

Pattern:

1. Export or inspect the source outside AgentGuard Graph.
2. Normalize it into local JSON or JSONL.
3. Run `agentguard-graph validate --json ...`.
4. Keep unknowns explicit.

### `agentguard.json`

```json
{
  "schema_version": "0.1",
  "agents": [
    {
      "id": "coding-agent",
      "name": "Coding Agent",
      "owner": "dev-platform",
      "runtime": "custom-agent-platform",
      "environment": "production",
      "autonomy": "approval_required",
      "input_sources": ["pull_request_comment", "repository_content"],
      "tools": ["shell.run", "github.create_pr"],
      "identities": ["github:code-agent"],
      "tool_identity_bindings": [
        {"tool": "github.create_pr", "identity": "github:code-agent"}
      ],
      "memory": [],
      "approval_policy": "coding-agent-policy"
    }
  ],
  "input_sources": [
    {
      "id": "pull_request_comment",
      "trust": "untrusted",
      "description": "User-controlled pull request comments"
    }
  ],
  "memory_stores": []
}
```

`tool_identity_bindings` can also be declared at top level with an optional `agent` field, or generated with `collect --tool-identity-binding TOOL=IDENTITY`.

Accepted risk can be declared at top level when a reviewer approves a time-bound exception. Scope narrowly whenever possible.

```json
{
  "risk_acceptances": [
    {
      "id": "risk-support-001",
      "status": "accepted",
      "owner": "appsec",
      "reason": "Temporary exception while outbound redaction control is deployed.",
      "ticket": "SEC-123",
      "expires_at": "2999-12-31",
      "scope": {
        "agent": "support-triage-agent",
        "rule_id": "untrusted_input_to_sensitive_data_to_external_sink"
      }
    }
  ]
}
```

Matching findings and attack paths include `risk_status` and `accepted_risk`. Expired acceptances are reported as `acceptance_expired`; they do not suppress findings.

### `mcp-servers.json`

```json
{
  "schema_version": "0.1",
  "servers": [
    {
      "id": "coding-mcp",
      "name": "Coding MCP Server",
      "transport": "stdio",
      "auth": "unknown",
      "tools": [
        {
          "name": "shell.run",
          "description": "Run a shell command in the repository workspace",
          "risk_tags": ["command_execution", "filesystem_write"],
          "target_system": "local_workspace"
        }
      ]
    }
  ]
}
```

### `identity.json`

```json
{
  "schema_version": "0.1",
  "identities": [
    {
      "id": "github:code-agent",
      "type": "github_app",
      "target_system": "github",
      "scopes": [],
      "permissions": [
        {
          "resource": "repo:*",
          "actions": ["read", "write"],
          "data_classes": ["source_code"],
          "confidence": "high"
        }
      ]
    }
  ]
}
```

### `data-catalog.json`

```json
{
  "schema_version": "0.1",
  "data_sources": [
    {
      "id": "repo:*",
      "name": "GitHub repositories",
      "target_system": "github",
      "data_classes": ["source_code"],
      "sensitivity": "high"
    }
  ]
}
```

### `approval-policy.json`

```json
{
  "schema_version": "0.1",
  "policies": [
    {
      "id": "coding-agent-policy",
      "rules": [
        {
          "id": "repo-write-requires-approval",
          "match": {"risk_tag": "repository_write"},
          "decision": "approval_required",
          "controls": ["audit_logging"],
          "reason": "Repository write actions require review"
        }
      ]
    }
  ]
}
```

Supported control tags include `sandbox_control`, `egress_allowlist`, `scoped_identity`, `read_only_identity`, `command_allowlist`, `secret_denylist`, `amount_threshold`, `audit_logging`, `change_ticket_required`, and `dlp_redaction`.

Scan reports also include `offline_control_analysis`. This section maps declared tools, flags generic command/filesystem/network/query surfaces, checks high-risk tools against the local approval-policy controls above, reports prompt-language security boundaries when prompts appear to carry security decisions that should live in policy or permission evidence, and produces a prioritized remediation roadmap with affected tools, agents, controls, and evidence requests.

OPA/Rego and Cedar importers may also add `policy_evaluations`. These preserve the imported decision, engine, match context, source file, and raw result for review.

### `events.jsonl`

```jsonl
{"event_type":"agent.tool_call","timestamp":"2026-05-17T10:00:00Z","agent":"coding-agent","session_id":"s1","input_source":"pull_request_comment","input_trust":"untrusted","tool":"shell.run","action_class":"command_execution","decision":"allow","confidence":"high"}
{"event_type":"agent.tool_call","timestamp":"2026-05-17T10:00:05Z","agent":"coding-agent","session_id":"s1","tool":"github.create_pr","action_class":"repository_write","decision":"blocked","policy":"repo-write-requires-approval","confidence":"high"}
```

## 7. Validate Evidence

```bash
agentguard-graph validate --json \
  --agents agent-evidence/agentguard.json \
  --mcp agent-evidence/mcp-servers.json \
  --identity agent-evidence/identity.json \
  --data-catalog agent-evidence/data-catalog.json \
  --approval-policy agent-evidence/approval-policy.json \
  --events agent-evidence/events.jsonl
```

With collected OpenAPI files:

```bash
agentguard-graph validate --json \
  --agents agent-evidence/agentguard.json \
  --mcp agent-evidence/mcp-servers.json \
  --openapi agent-evidence/openapi/ \
  --identity agent-evidence/identity.json \
  --data-catalog agent-evidence/data-catalog.json \
  --approval-policy agent-evidence/approval-policy.json \
  --events agent-evidence/events.jsonl
```

Errors exit `2`. Warnings indicate missing or weak evidence; scan can still run and will report visibility gaps.

## 8. Generate The Risk Report

```bash
agentguard-graph scan \
  --simple \
  --agents agent-evidence/agentguard.json \
  --mcp agent-evidence/mcp-servers.json \
  --identity agent-evidence/identity.json \
  --data-catalog agent-evidence/data-catalog.json \
  --approval-policy agent-evidence/approval-policy.json \
  --events agent-evidence/events.jsonl \
  --out outputs/my-agent/agent-risk.json \
  --markdown outputs/my-agent/agent-risk.md \
  --html outputs/my-agent/agent-risk.html
```

JSON is the stable machine-readable report. Markdown is for review. HTML is a self-contained local visualization. `--simple` only changes Markdown and HTML presentation; it does not remove fields from the JSON output.

## 9. Inventory

```bash
agentguard-graph inventory \
  --evidence-dir agent-evidence/ \
  --out outputs/my-agent/inventory.json
```

Use inventory mode for normalized graph facts without attack-path scoring.

## 10. Explain One Path

```bash
agentguard-graph explain \
  --findings outputs/my-agent/agent-risk.json \
  --path-id path-<stable-id-from-report>
```

Path and finding ids are deterministic hashes derived from rule and path evidence.

## 11. Compare Two Reports

After two review cycles, compare saved JSON reports:

```bash
agentguard-graph compare \
  --base outputs/previous/agent-risk.json \
  --head outputs/current/agent-risk.json \
  --base-label previous \
  --head-label current \
  --out outputs/current/agent-risk-compare.json \
  --markdown outputs/current/agent-risk-compare.md
```

The compare output reports new, resolved, improved, regressed, changed, and unchanged findings. It also reports new and resolved visibility gaps.

You can also compare evidence pack directories directly. The command validates each pack, builds reports in memory, and then compares them:

```bash
agentguard-graph compare \
  --base previous-agent-evidence/ \
  --head current-agent-evidence/ \
  --out outputs/current/agent-risk-compare.json
```

## 12. Portfolio Rollup

For a review meeting, roll up saved reports across teams, environments, or business units:

```bash
agentguard-graph portfolio \
  --reports-dir outputs/ \
  --out outputs/portfolio.json \
  --markdown outputs/portfolio.md
```

The portfolio output scans recursively by default. It skips JSON files that are not AgentGuard risk reports and summarizes severity, path state, owners, environments, business units, visibility-gap priority, visibility-gap type, top findings, and top missing-evidence blockers.

## 13. Demo

```bash
agentguard-graph demo --simple
```

Outputs:

```text
outputs/demo/agent-risk.json
outputs/demo/agent-risk.md
outputs/demo/agent-risk.html
outputs/demo/inventory.json
```

The demo uses the `demo-enterprise` pack. It includes support, coding, release, finance, knowledge-assistant, and Microsoft 365 Copilot sales agents with static paths, allowed events, blocked events, approval events, memory gaps, delegated Microsoft 365 visibility gaps, and IAM visibility gaps.

Run `agentguard-graph demo` without `--simple` when you want the full reviewer report.
