# AI Execution Layer Security Gap Review

Date: 2026-05-29

This review maps the supplied AI security checklist against AgentGuard Graph's local-first analyzer. The current scope is intentionally offline: AgentGuard Graph reads local evidence, never executes tools, never calls live services, and does not claim runtime enforcement.

## Executive Summary

The offline feature set now covers every blogpost recommendation that can be assessed from local files:

- every declared tool is inventoried in `offline_control_analysis.tool_inventory`
- generic execution, filesystem, network, and query-like tools are flagged
- nested schema selectors such as customer ids, paths, queries, URLs, and resource ids need review-grade constraints before a tool is treated as narrow
- high-risk tools are checked against local policy evidence for approval, sandbox, egress, secret denylist, scoped identity, DLP, change-ticket, amount-threshold, and audit controls
- local approval policies are analyzed for broad allows, conflicting matching decisions, shadowed narrower rules, unmatched dead rules, and ineffective control declarations
- prompt-language security boundaries are detected when high-risk tool controls are incomplete
- offline reports now include a prioritized remediation roadmap and control coverage score
- secret-like evidence values are still handled by `doctor`, and secret-capable tools are reviewed through risk tags and offline controls
- reports emit first-class findings for `offline_tool_control_gap`, `generic_tool_surface`, and `system_prompt_security_boundary`

Live gateway behavior, production runtime enforcement, runtime egress proof, key rotation, and incident reconstruction remain out of scope for the offline-only approach.

## Checklist Mapping

| Blogpost Control | Offline AgentGuard Support | Status |
| --- | --- | --- |
| Treat AI as an execution layer | Agent, tool, MCP server, OpenAPI operation, identity, data, memory, input source, policy, and event evidence are graph nodes/edges. `offline_control_analysis` now inventories each declared tool and high-risk tag. | Implemented offline |
| Map every tool the AI can call | `collect` imports local MCP config, OpenAPI JSON, Copilot packages, OpenClaw, LangChain/custom manifests, LangGraph config, static framework scans, and explicit manifests. | Implemented offline |
| Remove generic tools like `run_command` | Generic command/filesystem/network/query surfaces now produce `generic_tool_surface` findings and generic-tool inventory rows. | Implemented offline |
| Make tools narrow, typed, and permission checked | OpenAPI/MCP descriptors, schemas, security scopes, IAM binding coverage, least-privilege analysis, broad schema checks, and recursive review-grade selector constraint checks are represented in reports. | Implemented offline |
| Assume prompt injection will happen | Untrusted/mixed input sources drive attack paths; prompt-language security boundary anti-patterns now produce findings when offline controls are incomplete. | Implemented offline |
| Stop relying on system prompts for security | The scanner now flags prompt text such as "never reveal secrets" when high-risk tool controls are not backed by local policy evidence. | Implemented offline |
| Authorization checks and policy engines | Approval policy evidence supports allow, approval_required, deny, OPA/Rego and Cedar evaluation imports, local policy context gaps, and policy-rule risk analysis for broad allows, conflicting matches, shadowed narrower rules, unmatched rules, and ineffective control rules. | Implemented offline |
| Policy engines, sandboxed runtimes, tool gateways, network rules, approval flows | Offline control requirements now check for policy decisions and local control tags: sandbox, egress, command allowlist, secret denylist, scoped identity, DLP, amount threshold, change ticket, and audit logging. | Implemented as evidence review |
| Keep secrets away from the AI runtime | `doctor` scans evidence files without printing raw secret values; `secret_access` tools require scoped identity, secret denylist, approval/deny policy, and audit logging in offline analysis. | Implemented offline |
| Lock down sandbox and egress | Command, filesystem, network, and external-send tools now get missing-control findings if local evidence lacks sandbox or egress controls. | Implemented offline |
| Log every tool call | Runtime logs are outside the offline-only focus, but high-risk tool policies now require `audit_logging` evidence. | Implemented as static policy expectation |

## Implemented Artifacts

- `src/agentguard_graph/offline_analysis.py`: builds offline execution-layer control analysis, control coverage, and remediation roadmap items.
- `src/agentguard_graph/policy_analysis.py`: analyzes local policy rules for broad effective allows, conflicting matching decisions, shadowed narrower rules, unmatched dead rules, and ineffective control declarations.
- `src/agentguard_graph/graph/paths.py`: emits offline control findings and visibility gaps.
- `src/agentguard_graph/graph/findings.py`: includes `offline_control_analysis` in JSON reports and summary counters.
- `src/agentguard_graph/outputs/markdown.py`: renders offline execution-layer control summaries and policy-rule risk summaries.
- `src/agentguard_graph/outputs/html.py`: renders the same analysis in self-contained HTML.
- `schemas/findings.schema.json`: declares `offline_control_analysis` and `policy_analysis.rule_risks`.
- `tests/test_offline_analysis.py`: covers generic-tool, missing-control, and prompt-boundary detection.
- `tests/test_policy_analysis.py`: covers policy broad-allow, shadowing, and conflicting-decision detection.

## Remaining Out Of Scope

These blogpost items require live runtime or production platform evidence and are intentionally not implemented in the offline-only product track:

- actual tool gateway enforcement
- tenant/resource authorization enforcement at request time
- live rate limiting
- proof that cloud metadata or outbound network access is blocked at runtime
- production secret manager inventory and key rotation state
- incident-grade proof of who asked and what bytes left the boundary

The offline analyzer can request local evidence for those controls, but it should not claim they are enforced unless a separate runtime/export producer supplies verifiable local evidence.
