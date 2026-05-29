"""Evidence onboarding and handoff safety checks."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from . import __version__
from .graph.builder import build_graph
from .graph.paths import analyze_attack_paths
from .manifest import validate_evidence_manifest
from .schemas import DANGEROUS_TAGS, SENSITIVE_DATA_CLASSES, infer_target_system
from .validation.validate_inputs import ValidationResult, all_tools


MAX_SECRET_SCAN_BYTES = 2_000_000
SECRET_FILE_NAMES = {
    "agentguard.json",
    "mcp-servers.json",
    "identity.json",
    "data-catalog.json",
    "approval-policy.json",
    "events.jsonl",
    "collector-summary.json",
}
SECRET_EXTENSIONS = {".json", ".jsonl"}
PLACEHOLDER_VALUES = {
    "",
    "unknown",
    "none",
    "null",
    "redacted",
    "<redacted>",
    "replace-me",
    "replace_me",
    "changeme",
    "change-me",
    "example",
    "example-secret",
    "test",
    "dummy",
}
SECRET_KEY_HINTS = {
    "access_token",
    "api_key",
    "apikey",
    "auth_header",
    "authorization",
    "bearer",
    "client_secret",
    "credential",
    "credentials",
    "cookie",
    "jwt",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "session_cookie",
    "signing_secret",
    "token",
    "webhook_secret",
}
SECRET_PATTERNS: list[tuple[str, str, str, re.Pattern[str]]] = [
    (
        "private_key_block",
        "Private key block",
        "critical",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    ),
    (
        "aws_access_key",
        "AWS access key id",
        "high",
        re.compile(r"\b(?:AKIA|ASIA|A3T[A-Z0-9])[A-Z0-9]{16}\b"),
    ),
    (
        "github_token",
        "GitHub token",
        "high",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    ),
    (
        "slack_token",
        "Slack token",
        "high",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    (
        "google_api_key",
        "Google API key",
        "high",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    (
        "openai_api_key",
        "OpenAI-style API key",
        "high",
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "jwt",
        "JWT-like bearer token",
        "high",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    (
        "bearer_token",
        "Bearer token",
        "high",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    ),
]
TARGET_EXPORT_HINTS = {
    "github": {
        "file": "identity.json",
        "flag": "--github-app-export github-app-permissions.json",
        "exact_export": "Export GitHub App permissions and repository access. Do not include private keys or webhook secrets.",
    },
    "slack": {
        "file": "identity.json",
        "flag": "--oauth-scopes-export slack-oauth-scopes.json",
        "exact_export": "Export Slack OAuth scopes from the app/admin console. Do not include bot tokens, signing secrets, or refresh tokens.",
    },
    "google_workspace": {
        "file": "identity.json",
        "flag": "--oauth-scopes-export google-oauth-scopes.json",
        "exact_export": "Export Google Workspace OAuth scopes from the app/admin console. Do not include client secrets or refresh tokens.",
    },
    "salesforce": {
        "file": "identity.json",
        "flag": "--salesforce-permissions-export salesforce-permissions.json",
        "exact_export": "Export Salesforce connected app, profile, or permission-set object permissions. Do not include client secrets.",
    },
    "aws": {
        "file": "identity.json",
        "flag": "--aws-iam-policy aws-iam-policy.json",
        "exact_export": "Export the AWS IAM role or policy document used by the agent. Do not include access keys or session tokens.",
    },
    "kubernetes": {
        "file": "identity.json",
        "flag": "--kubernetes-rbac kubernetes-rbac.json",
        "exact_export": "Export Kubernetes Role or ClusterRole RBAC JSON for the agent service account. Do not include service-account tokens.",
    },
    "microsoft_365": {
        "file": "identity.json",
        "flag": "--microsoft-365-permissions microsoft-365-permissions.json",
        "exact_export": "Export Microsoft 365, Graph, Copilot connector, Teams, SharePoint, and mailbox permissions used by the agent. Do not include client secrets or refresh tokens.",
    },
    "azure": {
        "file": "identity.json",
        "flag": "--azure-rbac azure-rbac.json",
        "exact_export": "Export Azure RBAC role assignments for the managed identity, service principal, or workload identity used by the agent. Do not include credentials.",
    },
    "gcp": {
        "file": "identity.json",
        "flag": "--gcp-iam-policy gcp-iam-policy.json",
        "exact_export": "Export Google Cloud IAM bindings for the agent service account. Do not include service-account keys.",
    },
    "dataverse": {
        "file": "identity.json",
        "flag": "--dataverse-permissions dataverse-permissions.json",
        "exact_export": "Export Dataverse security roles, table privileges, and app user permissions used by the agent.",
    },
    "power_platform": {
        "file": "identity.json",
        "flag": "--power-platform-permissions power-platform-permissions.json",
        "exact_export": "Export Power Platform app, flow, connector, DLP, and approval permissions used by the agent.",
    },
}
GAP_PRIORITY_ORDER = {"critical_gap": 0, "high_gap": 1, "medium_gap": 2, "low_gap": 3}
EXPORT_PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2}
PROFILE_ALIASES = {
    "developer": "developer",
    "agent-developer": "developer",
    "agent_developer": "developer",
    "platform": "developer",
    "platform-team": "developer",
    "platform_team": "developer",
    "iam-admin": "iam_admin",
    "iam_admin": "iam_admin",
    "iam": "iam_admin",
    "data-owner": "data_owner",
    "data_owner": "data_owner",
    "privacy": "data_owner",
    "security-reviewer": "security_reviewer",
    "security_reviewer": "security_reviewer",
    "appsec": "security_reviewer",
    "appsec-reviewer": "security_reviewer",
    "appsec_reviewer": "security_reviewer",
}
PROFILE_LABELS = {
    "developer": "Agent developer / platform team",
    "iam_admin": "IAM admin",
    "data_owner": "Data owner",
    "security_reviewer": "Security reviewer",
}
PROFILE_RESPONSIBILITIES = {
    "developer": [
        "Produce agent inventory, tool descriptors, local framework evidence, and runtime context.",
        "Fix missing references between agentguard.json, mcp-servers.json, openapi/, and generated evidence.",
    ],
    "iam_admin": [
        "Export target-system permissions, scopes, roles, grants, and tool-to-identity bindings.",
        "Redact tokens, private keys, client secrets, and refresh tokens before handoff.",
    ],
    "data_owner": [
        "Classify target systems, resources, memory stores, and sensitive data classes.",
        "Provide retention or deletion evidence for persistent memory that stores sensitive data.",
    ],
    "security_reviewer": [
        "Review approval, deny, sandbox, egress, DLP, and audit controls for sensitive tools.",
        "Confirm secret findings are redacted and validation blockers are resolved before packaging.",
    ],
}
ACTION_KIND_PROFILES = {
    "agent_inventory": {"developer", "security_reviewer"},
    "agent_metadata": {"developer"},
    "project_collection": {"developer"},
    "tool_descriptor": {"developer"},
    "tool_manifest": {"developer"},
    "input_sources": {"developer", "security_reviewer"},
    "memory_reference": {"developer", "data_owner"},
    "memory_retention": {"developer", "data_owner", "security_reviewer"},
    "identity_permissions": {"iam_admin", "security_reviewer"},
    "data_classification": {"data_owner", "security_reviewer"},
    "approval_controls": {"security_reviewer", "developer"},
    "runtime_events": {"developer", "security_reviewer"},
}
ACTION_KIND_OWNER = {
    "agent_inventory": "agent developer",
    "agent_metadata": "agent developer",
    "project_collection": "agent developer",
    "tool_descriptor": "platform team",
    "tool_manifest": "platform team",
    "input_sources": "agent developer",
    "memory_reference": "agent developer",
    "memory_retention": "data owner",
    "identity_permissions": "IAM admin",
    "data_classification": "data owner",
    "approval_controls": "security reviewer",
    "runtime_events": "platform team",
}
FRAMEWORK_CHECKLISTS = {
    "copilot": {
        "label": "Microsoft 365 Copilot agents",
        "owner": "platform team",
        "source_keys": ("copilot_agent",),
        "steps": [
            {
                "file": "agentguard.json",
                "owner": "agent developer",
                "reason": "Copilot declarative agent metadata defines prompts, inputs, conversation starters, and plugin references.",
                "repair_text": "Run collect with --copilot-agent pointing at the app package directory, zip, or manifest JSON so agentguard.json includes the Copilot agent id, runtime, tools, and input source.",
                "command": "agentguard-graph collect --out agent-evidence/ --copilot-agent path/to/appPackage",
            },
            {
                "file": "mcp-servers.json or openapi/",
                "owner": "platform team",
                "reason": "Copilot plugins and actions need tool descriptors so reviewers can map prompts to target systems and risk tags.",
                "repair_text": "Include plugin OpenAPI JSON, declarative action metadata, remote MCP descriptors, and built-in Copilot capabilities without embedding credentials.",
                "command": "agentguard-graph collect --out agent-evidence/ --copilot-agent path/to/appPackage --openapi path/to/openapi.json",
            },
            {
                "file": "identity.json",
                "owner": "IAM admin",
                "reason": "Copilot agents often use Microsoft Graph, connector, Dataverse, Power Platform, or OAuth permissions.",
                "repair_text": "Export Microsoft 365, Graph, connector, Dataverse, Power Platform, and OAuth permission grants. Redact client secrets and refresh tokens.",
                "command": "agentguard-graph collect --out agent-evidence/ --microsoft-365-permissions microsoft-365-permissions.json",
            },
        ],
    },
    "mcp": {
        "label": "MCP tools",
        "owner": "platform team",
        "source_keys": ("mcp_config",),
        "steps": [
            {
                "file": "mcp-servers.json",
                "owner": "platform team",
                "reason": "MCP list-tools output is the source of truth for callable tool names, descriptions, transports, and risk tags.",
                "repair_text": "Export MCP client config or list-tools metadata for every server used by the agent. Do not include server auth tokens.",
                "command": "agentguard-graph collect --out agent-evidence/ --mcp-config path/to/mcp-config.json",
            },
            {
                "file": "identity.json",
                "owner": "IAM admin",
                "reason": "Each MCP tool should be tied to the identity and target-system permissions it uses.",
                "repair_text": "Export the permissions for the service account, OAuth client, app registration, or role behind each MCP server, then add tool_identity_bindings when multiple identities are present.",
                "command": "agentguard-graph collect --out agent-evidence/ --oauth-scopes-export oauth-scopes.json",
            },
            {
                "file": "approval-policy.json",
                "owner": "security reviewer",
                "reason": "Dangerous MCP tools need explicit approval, deny, sandbox, egress, or audit controls.",
                "repair_text": "Add policy rules for command execution, external sends, writes, deletes, financial actions, and sensitive reads.",
                "command": "agentguard-graph doctor --evidence-dir agent-evidence/ --profile security-reviewer",
            },
        ],
    },
    "langgraph": {
        "label": "LangGraph config",
        "owner": "agent developer",
        "source_keys": ("langgraph_config",),
        "steps": [
            {
                "file": "agentguard.json",
                "owner": "agent developer",
                "reason": "LangGraph graphs identify agent entrypoints but do not always include full tool, identity, or runtime evidence.",
                "repair_text": "Run collect with --langgraph-config, then enrich generated agentguard.json with owner, environment, autonomy, input sources, identities, and tool-to-identity bindings.",
                "command": "agentguard-graph collect --out agent-evidence/ --langgraph-config langgraph.json",
            },
            {
                "file": "mcp-servers.json or openapi/",
                "owner": "platform team",
                "reason": "LangGraph nodes may call tools declared in code, MCP config, OpenAPI files, or custom manifests.",
                "repair_text": "Add MCP configs, OpenAPI JSON, or tool manifests that define every tool id referenced by the graph.",
                "command": "agentguard-graph collect --out agent-evidence/ --langgraph-config langgraph.json --mcp-config path/to/mcp.json --openapi path/to/openapi.json",
            },
        ],
    },
    "langchain_custom_manifest": {
        "label": "LangChain/custom tool manifests",
        "owner": "agent developer",
        "source_keys": ("tool_manifest",),
        "steps": [
            {
                "file": "mcp-servers.json",
                "owner": "agent developer",
                "reason": "Local manifests provide deterministic tool ids, descriptions, risk tags, target systems, and input schemas.",
                "repair_text": "Export a JSON manifest with agents, tools, input sources, identities, and optional data sources; keep runtime secrets out of the manifest.",
                "command": "agentguard-graph collect --out agent-evidence/ --langchain-manifest langchain-tools.json",
            },
            {
                "file": "identity.json",
                "owner": "IAM admin",
                "reason": "Custom tools need permission evidence because code-level function names rarely prove least privilege.",
                "repair_text": "Export target-system permissions for every identity used by the manifest, then bind tools to identities when more than one identity exists.",
                "command": "agentguard-graph collect --out agent-evidence/ --oauth-scopes-export oauth-scopes.json",
            },
        ],
    },
    "static_framework_scan": {
        "label": "Static framework scans",
        "owner": "agent developer",
        "source_keys": ("framework_code",),
        "steps": [
            {
                "file": "collector-summary.json",
                "owner": "agent developer",
                "reason": "Static scans find framework imports and obvious tool references but cannot execute dynamic factories.",
                "repair_text": "Run --framework-code on the narrowest project path, review collector-summary.json warnings, and add explicit manifests for dynamic tools.",
                "command": "agentguard-graph collect --out agent-evidence/ --framework-code path/to/project",
            },
            {
                "file": "identity.json",
                "owner": "IAM admin",
                "reason": "Static code evidence does not prove the deployed identity or permissions used at runtime.",
                "repair_text": "Add deployed service account, OAuth client, app registration, role, grant, or permission-set exports for the scanned agent.",
                "command": "agentguard-graph doctor --evidence-dir agent-evidence/ --profile iam-admin",
            },
            {
                "file": "events.jsonl",
                "owner": "platform team",
                "reason": "Runtime events convert static tool reachability into observed or blocked behavior.",
                "repair_text": "Export redacted tool-call, approval, allow, block, and session-correlation events after static evidence is complete.",
                "command": "agentguard-graph doctor --evidence-dir agent-evidence/ --profile developer",
            },
        ],
    },
}


def conventional_evidence_files(evidence_dir: str | None, evidence_paths: dict[str, str]) -> list[Path]:
    paths: list[Path] = []
    if evidence_dir:
        base = Path(evidence_dir)
        for name in sorted(SECRET_FILE_NAMES):
            candidate = base / name
            if candidate.is_file():
                paths.append(candidate)
        for openapi_base in [base / "openapi", Path(evidence_paths.get("openapi", "")) if evidence_paths.get("openapi") else None]:
            if openapi_base and openapi_base.is_dir():
                paths.extend(sorted(openapi_base.glob("*.json")))
    for path_value in evidence_paths.values():
        if not path_value:
            continue
        path = Path(path_value)
        if path.is_dir():
            paths.extend(sorted(item for item in path.glob("*.json") if item.is_file()))
        elif path.is_file():
            paths.append(path)
    return _unique_paths(paths)


def discovered_project_files(discovered_inputs: dict[str, list[str]] | None) -> list[Path]:
    if not discovered_inputs:
        return []
    return _unique_paths(
        [Path(path) for paths in discovered_inputs.values() for path in paths if Path(path).is_file()]
    )


def build_doctor_report(
    *,
    evidence: dict[str, Any],
    validation: ValidationResult,
    evidence_paths: dict[str, str],
    evidence_dir: str | None = None,
    project_dir: str | None = None,
    discovered_inputs: dict[str, list[str]] | None = None,
    profile: str | None = None,
) -> dict[str, Any]:
    secret_paths = conventional_evidence_files(evidence_dir, evidence_paths)
    if not secret_paths and discovered_inputs:
        secret_paths = discovered_project_files(discovered_inputs)
    manifest_status = validate_evidence_manifest(evidence_dir, secret_paths)
    secret_findings, skipped_secret_files = scan_secret_files(secret_paths)
    visibility_gaps: list[dict[str, Any]] = []
    if validation.ok:
        graph, graph_gaps = build_graph(evidence)
        _, findings, gaps = analyze_attack_paths(evidence, graph_gaps)
        visibility_gaps = [gap.to_dict() for gap in gaps]
        affected_findings = len(findings)
    else:
        affected_findings = 0
    evidence_sources = _evidence_source_status(evidence)
    recommended_exports = _recommended_exports(evidence, validation, visibility_gaps)
    project_discovery = _project_discovery(project_dir, discovered_inputs)
    if project_discovery and project_discovery["recommended_collect_command"]:
        _add_recommendation(
            recommended_exports,
            priority="P0" if not evidence_sources["agent_inventory"]["count"] else "P1",
            kind="project_collection",
            file="agentguard.json",
            target="project",
            reason="Run collection from the agent project so local config evidence becomes a reviewed evidence pack.",
            exact_export="Run the generated collect command, then review and enrich the evidence files before handoff.",
            command=project_discovery["recommended_collect_command"],
        )
    status = _status(validation, secret_findings, recommended_exports)
    blockers = _blockers(validation, secret_findings)
    has_evidence_files = any(evidence_paths.values())
    package_ready = not blockers and has_evidence_files
    next_commands = _next_commands(evidence_dir, evidence_paths, project_discovery, package_ready, recommended_exports)
    normalized_profile = normalize_profile(profile)
    framework_checklists = _framework_checklists(evidence, discovered_inputs, recommended_exports)
    collection_plan = _collection_plan(
        evidence=evidence,
        evidence_dir=evidence_dir,
        project_dir=project_dir,
        status=status,
        package_ready=package_ready,
        recommended_exports=recommended_exports,
        framework_checklists=framework_checklists,
        profile=normalized_profile,
    )
    profile_view = _profile_view(collection_plan, normalized_profile)
    return {
        "schema_version": "0.1",
        "tool": {"name": "agentguard-graph", "version": __version__},
        "status": status,
        "package_ready": package_ready,
        "blockers": blockers,
        "summary": {
            "evidence_files_checked": len(secret_paths),
            "secret_findings": len(secret_findings),
            "secret_files_skipped": len(skipped_secret_files),
            "validation_errors": len(validation.errors),
            "validation_warnings": len(validation.warnings),
            "recommended_exports": len(recommended_exports),
            "priority_exports": sum(1 for item in recommended_exports if item["priority"] in {"P0", "P1"}),
            "visibility_gaps": len(visibility_gaps),
            "affected_findings": affected_findings,
            "manifest_status": manifest_status["status"],
            "manifest_checked": manifest_status["summary"]["checked_count"],
            "manifest_changed": manifest_status["summary"]["changed_count"],
            "manifest_missing": manifest_status["summary"]["missing_count"],
            "manifest_unmanifested": manifest_status["summary"]["unmanifested_count"],
        },
        "manifest": manifest_status,
        "validation": validation.to_dict(),
        "evidence_sources": list(evidence_sources.values()),
        "recommended_exports": recommended_exports,
        "secret_findings": secret_findings,
        "skipped_secret_files": skipped_secret_files,
        "project_discovery": project_discovery,
        "collection_plan": collection_plan,
        "profile_view": profile_view,
        "framework_checklists": framework_checklists,
        "top_visibility_gaps": _top_visibility_gaps(visibility_gaps),
        "next_commands": next_commands,
    }


def normalize_profile(profile: str | None) -> str:
    if not profile:
        return ""
    normalized = profile.strip().lower().replace(" ", "-")
    return PROFILE_ALIASES.get(normalized, "")


def _collection_plan(
    *,
    evidence: dict[str, Any],
    evidence_dir: str | None,
    project_dir: str | None,
    status: str,
    package_ready: bool,
    recommended_exports: list[dict[str, Any]],
    framework_checklists: list[dict[str, Any]],
    profile: str,
) -> dict[str, Any]:
    actions = [_collection_action(index, item) for index, item in enumerate(recommended_exports, start=1)]
    return {
        "schema_version": "0.1",
        "plan_type": "agentguard_graph_collection_plan",
        "profile": profile or "all",
        "status": status,
        "package_ready": package_ready,
        "source": {
            "evidence_dir": evidence_dir or "",
            "project_dir": project_dir or "",
        },
        "summary": {
            "actions": len(actions),
            "p0_actions": sum(1 for action in actions if action["priority"] == "P0"),
            "p1_actions": sum(1 for action in actions if action["priority"] == "P1"),
            "framework_checklists": len(framework_checklists),
            "agents": len((evidence.get("agents") or {}).get("agents") or []),
            "tools": len(all_tools(evidence)),
            "identities": len((evidence.get("identity") or {}).get("identities") or []),
        },
        "actions": actions,
        "framework_checklists": framework_checklists,
    }


def _collection_action(index: int, item: dict[str, Any]) -> dict[str, Any]:
    kind = str(item.get("kind", "evidence"))
    profiles = sorted(ACTION_KIND_PROFILES.get(kind, {"developer", "security_reviewer"}))
    return {
        "id": f"collect-{index:03d}",
        "priority": str(item.get("priority", "P2")),
        "kind": kind,
        "owner": _action_owner(item),
        "profiles": profiles,
        "file": str(item.get("file", "")),
        "target": str(item.get("target", "")),
        "reason": str(item.get("reason", "")),
        "repair_category": _repair_category(item),
        "repair_text": _repair_text(item),
        "exact_export": str(item.get("exact_export", "")),
        "command": str(item.get("command", "")),
    }


def _action_owner(item: dict[str, Any]) -> str:
    kind = str(item.get("kind", ""))
    if kind == "identity_permissions":
        return "IAM admin"
    if kind == "data_classification":
        return "data owner"
    if kind == "approval_controls":
        return "security reviewer"
    return ACTION_KIND_OWNER.get(kind, "platform team")


def _repair_category(item: dict[str, Any]) -> str:
    kind = str(item.get("kind", ""))
    reason = str(item.get("reason", "")).lower()
    if "references unknown" in reason or "references identity" in reason or "references" in reason and "does not define" in reason:
        return "missing_reference"
    if kind == "identity_permissions":
        return "weak_identity_evidence"
    if kind == "data_classification":
        return "absent_data_classification"
    if kind == "approval_controls":
        return "missing_approval_policy"
    if kind in {"tool_descriptor", "input_sources", "memory_reference"}:
        return "missing_reference"
    return "evidence_gap"


def _repair_text(item: dict[str, Any]) -> str:
    kind = str(item.get("kind", ""))
    file_name = str(item.get("file", "evidence file"))
    target = str(item.get("target", "target"))
    if kind == "tool_descriptor":
        return (
            f"Missing reference repair: add a descriptor for `{target}` to {file_name}, or update "
            "agentguard.json so the agent tool id matches an exported MCP tool name or OpenAPI operation id exactly."
        )
    if kind == "identity_permissions":
        return (
            f"Weak identity evidence repair: update {file_name} with the identity, target_system, scopes, roles, "
            f"resource permissions, and confidence for `{target}`. Export from the target admin console and redact secrets."
        )
    if kind == "data_classification":
        return (
            f"Absent data classification repair: update {file_name} with data source ids, target_system, resource, "
            f"sensitivity, data_classes, and owner for `{target}` so sensitive reachability can be reviewed."
        )
    if kind == "approval_controls":
        return (
            f"Missing approval policy repair: update {file_name} with rules matching `{target}` and include decision, "
            "controls, approver or ticket requirements, deny/sandbox/egress/DLP controls, and audit expectations."
        )
    if kind == "input_sources":
        return (
            f"Missing reference repair: add `{target}` under agentguard.json input_sources with trust and description, "
            "or remove the stale reference from the agent."
        )
    if kind == "memory_reference":
        return (
            f"Missing reference repair: add `{target}` under agentguard.json memory_stores with persistence, "
            "data_classes, sensitivity, and retention_policy, or remove the stale memory reference from the agent."
        )
    if kind == "memory_retention":
        return (
            f"Memory evidence repair: update {file_name} for `{target}` with retention period, deletion workflow, "
            "redaction controls, owner, and approval or audit evidence."
        )
    if kind == "agent_inventory":
        return (
            "Agent inventory repair: create agentguard.json with every agent id, owner, runtime, environment, "
            "autonomy, input_sources, tools, identities, memory, and approval_policy references."
        )
    if kind == "agent_metadata":
        return f"Agent metadata repair: update {file_name} for `{target}` with owner and deployed environment."
    if kind == "project_collection":
        return "Project collection repair: run the generated collect command, then review generated evidence before handoff."
    if kind == "runtime_events":
        return (
            "Runtime evidence repair: export redacted JSONL events with event_type, session_id, timestamp, agent, tool, "
            "decision or outcome, data_classes, and policy evidence when available."
        )
    return str(item.get("exact_export", "Add the missing evidence, then run doctor again."))


def _profile_view(collection_plan: dict[str, Any], profile: str) -> dict[str, Any]:
    if not profile:
        return {
            "profile": "all",
            "label": "All roles",
            "responsibilities": [],
            "actions": collection_plan.get("actions", []),
            "hidden_action_count": 0,
            "framework_checklists": collection_plan.get("framework_checklists", []),
        }
    actions = [
        action
        for action in collection_plan.get("actions", [])
        if profile in action.get("profiles", [])
    ]
    checklists = _profile_checklists(collection_plan.get("framework_checklists", []), profile)
    return {
        "profile": profile,
        "label": PROFILE_LABELS.get(profile, profile),
        "responsibilities": PROFILE_RESPONSIBILITIES.get(profile, []),
        "actions": actions,
        "hidden_action_count": len(collection_plan.get("actions", [])) - len(actions),
        "framework_checklists": checklists,
    }


def _profile_checklists(checklists: list[dict[str, Any]], profile: str) -> list[dict[str, Any]]:
    profile_owner = PROFILE_LABELS.get(profile, "").lower()
    if profile == "developer":
        owner_terms = {"agent developer", "platform team"}
    elif profile == "iam_admin":
        owner_terms = {"iam admin"}
    elif profile == "data_owner":
        owner_terms = {"data owner"}
    elif profile == "security_reviewer":
        owner_terms = {"security reviewer"}
    else:
        owner_terms = {profile_owner}
    filtered = []
    for checklist in checklists:
        steps = [
            step
            for step in checklist.get("steps", [])
            if str(step.get("owner", "")).lower() in owner_terms
        ]
        if steps or checklist.get("status") == "detected":
            cloned = dict(checklist)
            cloned["steps"] = steps or checklist.get("steps", [])
            filtered.append(cloned)
    return filtered


def _framework_checklists(
    evidence: dict[str, Any],
    discovered_inputs: dict[str, list[str]] | None,
    recommended_exports: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    discovered_inputs = discovered_inputs or {}
    checklists = []
    for framework_id, spec in FRAMEWORK_CHECKLISTS.items():
        source_files = _framework_source_files(spec, discovered_inputs)
        detected = _framework_detected(framework_id, evidence, source_files)
        steps = [_framework_step(step, evidence) for step in spec["steps"]]
        matching_actions = [
            str(action.get("id", ""))
            for action in [_collection_action(index, item) for index, item in enumerate(recommended_exports, start=1)]
            if _action_matches_framework(framework_id, action)
        ]
        checklists.append(
            {
                "id": framework_id,
                "label": spec["label"],
                "status": "detected" if detected else "not_detected",
                "owner": spec["owner"],
                "source_files": source_files,
                "steps": steps,
                "related_plan_actions": [action_id for action_id in matching_actions if action_id],
            }
        )
    return checklists


def _framework_source_files(spec: dict[str, Any], discovered_inputs: dict[str, list[str]]) -> list[str]:
    files: list[str] = []
    for key in spec.get("source_keys", ()):
        files.extend(discovered_inputs.get(key, []))
    return _unique_strings(files)


def _framework_step(step: dict[str, str], evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "file": step["file"],
        "owner": step["owner"],
        "reason": step["reason"],
        "repair_text": step["repair_text"],
        "command": step["command"],
        "done": _framework_step_done(step["file"], evidence),
    }


def _framework_step_done(file_name: str, evidence: dict[str, Any]) -> bool:
    if file_name.startswith("agentguard.json"):
        return bool((evidence.get("agents") or {}).get("agents"))
    if file_name.startswith("mcp-servers.json") or "openapi" in file_name:
        return bool(all_tools(evidence))
    if file_name.startswith("identity.json"):
        identities = (evidence.get("identity") or {}).get("identities") or []
        return any(identity.get("permissions") or identity.get("scopes") for identity in identities)
    if file_name.startswith("data-catalog.json"):
        return bool((evidence.get("data_catalog") or {}).get("data_sources"))
    if file_name.startswith("approval-policy.json"):
        policies = (evidence.get("approval_policy") or {}).get("policies") or []
        return any(policy.get("rules") for policy in policies)
    if file_name.startswith("events.jsonl"):
        return bool((evidence.get("events") or {}).get("events"))
    return False


def _framework_detected(framework_id: str, evidence: dict[str, Any], source_files: list[str]) -> bool:
    if source_files:
        return True
    agents = (evidence.get("agents") or {}).get("agents") or []
    servers = (evidence.get("mcp") or {}).get("servers") or []
    if framework_id == "copilot":
        return any(agent.get("runtime") == "microsoft-365-copilot" for agent in agents) or any(
            server.get("transport") in {"copilot_plugin", "copilot_builtin", "remote_mcp"} for server in servers
        )
    if framework_id == "mcp":
        return bool(servers)
    if framework_id == "langgraph":
        return any("langgraph" in str(agent.get("runtime", "")).lower() for agent in agents) or any(
            "langgraph" in str((agent.get("labels") or {}).get("langgraph_graphs", "")).lower() for agent in agents
        )
    if framework_id == "langchain_custom_manifest":
        return any(server.get("transport") == "local_manifest" for server in servers)
    if framework_id == "static_framework_scan":
        return any(server.get("transport") == "framework_static" for server in servers) or any(
            (agent.get("labels") or {}).get("collector") == "framework_code_static" for agent in agents
        )
    return False


def _action_matches_framework(framework_id: str, action: dict[str, Any]) -> bool:
    if framework_id == "copilot":
        text = _action_text(action)
        return "copilot" in text or "microsoft_365" in text or "microsoft 365" in text
    if framework_id == "mcp":
        return "mcp" in _action_text(action)
    if framework_id == "langgraph":
        return "langgraph" in _action_text(action)
    if framework_id == "langchain_custom_manifest":
        text = _action_text(action)
        return "manifest" in text or "langchain" in text
    if framework_id == "static_framework_scan":
        text = _action_text(action)
        return "framework" in text or "static" in text
    return False


def _action_text(action: dict[str, Any]) -> str:
    return " ".join(str(action.get(field, "")) for field in ["kind", "file", "target", "reason", "exact_export", "command"]).lower()


def scan_secret_files(paths: list[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for path in _unique_paths(paths):
        if path.suffix.lower() not in SECRET_EXTENSIONS:
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            skipped.append({"file": str(path), "reason": f"cannot stat file: {exc}"})
            continue
        if size > MAX_SECRET_SCAN_BYTES:
            skipped.append({"file": str(path), "reason": f"file larger than {MAX_SECRET_SCAN_BYTES} bytes"})
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            skipped.append({"file": str(path), "reason": "file is not UTF-8 text"})
            continue
        except OSError as exc:
            skipped.append({"file": str(path), "reason": f"cannot read file: {exc}"})
            continue
        _extend_unique(findings, seen, _line_secret_findings(path, text))
        _extend_unique(findings, seen, _json_secret_findings(path, text))
    for index, finding in enumerate(findings, start=1):
        finding["id"] = f"secret-{index:03d}"
    return findings, skipped


def _line_secret_findings(path: Path, text: str) -> list[dict[str, Any]]:
    findings = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for finding_type, label, severity, pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            findings.append(
                _secret_finding(
                    file=path,
                    line=line_no,
                    json_path="",
                    finding_type=finding_type,
                    label=label,
                    severity=severity,
                    value=match.group(0),
                    reason=f"{label} pattern appears in evidence text. Redact before packaging.",
                )
            )
    return findings


def _json_secret_findings(path: Path, text: str) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".jsonl":
        findings = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                item = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            findings.extend(_secret_findings_from_value(path, item, f"$line[{line_no}]", line_no))
        return findings
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    return _secret_findings_from_value(path, data, "$", None)


def _secret_findings_from_value(path: Path, value: Any, json_path: str, line: int | None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{json_path}.{_json_path_key(str(key))}"
            if _key_indicates_secret(str(key)) and _value_looks_secret(child):
                findings.append(
                    _secret_finding(
                        file=path,
                        line=line,
                        json_path=child_path,
                        finding_type="secret_field",
                        label="Secret-like field",
                        severity="high",
                        value=str(child),
                        reason=f"Field `{key}` appears to contain secret material. Replace with a redacted placeholder before packaging.",
                    )
                )
            findings.extend(_secret_findings_from_value(path, child, child_path, line))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(_secret_findings_from_value(path, child, f"{json_path}[{index}]", line))
    return findings


def _secret_finding(
    *,
    file: Path,
    line: int | None,
    json_path: str,
    finding_type: str,
    label: str,
    severity: str,
    value: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "severity": severity,
        "type": finding_type,
        "label": label,
        "file": str(file),
        "line": line,
        "json_path": json_path,
        "fingerprint": _fingerprint(value),
        "reason": reason,
        "redaction": "Remove the raw value or replace it with REDACTED before sending or packaging this evidence.",
    }


def _extend_unique(findings: list[dict[str, Any]], seen: set[tuple[Any, ...]], candidates: list[dict[str, Any]]) -> None:
    for candidate in candidates:
        key = (
            candidate.get("file"),
            candidate.get("line"),
            candidate.get("json_path"),
            candidate.get("type"),
            candidate.get("fingerprint"),
        )
        if key in seen:
            continue
        seen.add(key)
        findings.append(candidate)


def _key_indicates_secret(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
    if not normalized:
        return False
    parts = set(normalized.split("_"))
    if normalized in SECRET_KEY_HINTS or parts.intersection(SECRET_KEY_HINTS):
        return True
    return any(hint in normalized for hint in ["private_key", "client_secret", "refresh_token", "access_token"])


def _value_looks_secret(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if stripped.lower() in PLACEHOLDER_VALUES:
        return False
    if len(stripped) < 8:
        return False
    if stripped.startswith("${") and stripped.endswith("}"):
        return False
    return True


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _json_path_key(key: str) -> str:
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        return key
    return json.dumps(key)


def _evidence_source_status(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    agents = (evidence.get("agents") or {}).get("agents") or []
    input_sources = (evidence.get("agents") or {}).get("input_sources") or []
    memory = (evidence.get("agents") or {}).get("memory_stores") or []
    tools = all_tools(evidence)
    mcp_servers = (evidence.get("mcp") or {}).get("servers") or []
    identities = (evidence.get("identity") or {}).get("identities") or []
    data_sources = (evidence.get("data_catalog") or {}).get("data_sources") or []
    policies = (evidence.get("approval_policy") or {}).get("policies") or []
    events = (evidence.get("events") or {}).get("events") or []
    identities_without_permissions = [identity.get("id") for identity in identities if not identity.get("permissions")]
    agents_without_owner = [agent.get("id") for agent in agents if not agent.get("owner")]
    agents_without_environment = [
        agent.get("id") for agent in agents if agent.get("environment") in {"", "unknown", None}
    ]
    servers_without_tools = [server.get("id") for server in mcp_servers if not server.get("tools")]
    policies_without_rules = [policy.get("id") for policy in policies if not policy.get("rules")]
    return {
        "agent_inventory": {
            "kind": "agent_inventory",
            "file": "agentguard.json",
            "status": _source_status(len(agents), bool(agents_without_owner or agents_without_environment or not input_sources)),
            "count": len(agents),
            "notes": _notes(
                [
                    _count_note(agents_without_owner, "agents missing owner"),
                    _count_note(agents_without_environment, "agents missing environment"),
                    "no input sources declared" if agents and not input_sources else "",
                    _count_note(memory, "memory stores declared"),
                ]
            ),
        },
        "tool_manifest": {
            "kind": "tool_manifest",
            "file": "mcp-servers.json or openapi/",
            "status": _source_status(len(tools), bool(servers_without_tools)),
            "count": len(tools),
            "notes": _notes([_count_note(servers_without_tools, "MCP servers missing tool descriptors")]),
        },
        "identity_permissions": {
            "kind": "identity_permissions",
            "file": "identity.json",
            "status": _source_status(len(identities), bool(identities_without_permissions)),
            "count": len(identities),
            "notes": _notes([_count_note(identities_without_permissions, "identities missing permissions/scopes")]),
        },
        "data_classification": {
            "kind": "data_classification",
            "file": "data-catalog.json",
            "status": _source_status(len(data_sources)),
            "count": len(data_sources),
            "notes": "classifies target systems, resources, and memory stores",
        },
        "approval_controls": {
            "kind": "approval_controls",
            "file": "approval-policy.json",
            "status": _source_status(len(policies), bool(policies_without_rules)),
            "count": len(policies),
            "notes": _notes([_count_note(policies_without_rules, "policies without rules")]),
        },
        "runtime_events": {
            "kind": "runtime_events",
            "file": "events.jsonl",
            "status": _source_status(len(events)),
            "count": len(events),
            "notes": "tool-call, approval, allowed, blocked, and memory events",
        },
    }


def _recommended_exports(
    evidence: dict[str, Any],
    validation: ValidationResult,
    visibility_gaps: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    recommendations: list[dict[str, Any]] = []
    agents = (evidence.get("agents") or {}).get("agents") or []
    input_sources = (evidence.get("agents") or {}).get("input_sources") or []
    memory_stores = (evidence.get("agents") or {}).get("memory_stores") or []
    tools = all_tools(evidence)
    tool_ids = {tool.get("id") for tool in tools if tool.get("id")}
    identities = (evidence.get("identity") or {}).get("identities") or []
    identity_ids = {identity.get("id") for identity in identities if identity.get("id")}
    input_ids = {item.get("id") for item in input_sources if item.get("id")}
    memory_ids = {item.get("id") for item in memory_stores if item.get("id")}
    data_sources = (evidence.get("data_catalog") or {}).get("data_sources") or []
    policies = (evidence.get("approval_policy") or {}).get("policies") or []
    policy_ids = {policy.get("id") for policy in policies if policy.get("id")}
    events = (evidence.get("events") or {}).get("events") or []

    if not agents:
        _add_recommendation(
            recommendations,
            priority="P0",
            kind="agent_inventory",
            file="agentguard.json",
            target="agents",
            reason="No agent inventory evidence was provided.",
            exact_export="Export or write agent id, owner, runtime, environment, autonomy, input sources, tool ids, identity ids, and memory stores.",
            command="agentguard-graph collect --project-dir . --out agent-evidence/",
        )
    for agent in agents:
        missing = []
        if not agent.get("owner"):
            missing.append("owner")
        if agent.get("environment") in {"", "unknown", None}:
            missing.append("environment")
        if missing:
            _add_recommendation(
                recommendations,
                priority="P1",
                kind="agent_metadata",
                file="agentguard.json",
                target=str(agent.get("id", "unknown-agent")),
                reason=f"Agent metadata is missing: {', '.join(missing)}.",
                exact_export="Add the owning team and deployment environment from the agent runtime, deployment manifest, or service catalog.",
                command="Edit agent-evidence/agentguard.json, then run agentguard-graph validate --evidence-dir agent-evidence/ --json",
            )
        for tool_id in agent.get("tools", []):
            if tool_id not in tool_ids:
                _add_recommendation(
                    recommendations,
                    priority="P0",
                    kind="tool_descriptor",
                    file="mcp-servers.json or openapi/",
                    target=str(tool_id),
                    reason=f"Agent {agent.get('id')} references {tool_id}, but no MCP/OpenAPI descriptor was provided.",
                    exact_export="Export MCP list-tools metadata or the OpenAPI JSON operation that defines this tool, including target_system and risk_tags when known.",
                    command="agentguard-graph collect --project-dir . --out agent-evidence/ --mcp-config path/to/mcp-config.json --openapi path/to/openapi.json",
                )
        for identity_id in agent.get("identities", []):
            if identity_id not in identity_ids:
                target = infer_target_system(identity_id)
                _add_target_export(
                    recommendations,
                    priority="P0",
                    target=target,
                    reason=f"Agent {agent.get('id')} references identity {identity_id}, but identity.json does not define it.",
                )
        for input_source_id in agent.get("input_sources", []):
            if input_source_id not in input_ids:
                _add_recommendation(
                    recommendations,
                    priority="P0",
                    kind="input_sources",
                    file="agentguard.json",
                    target=str(input_source_id),
                    reason=f"Agent {agent.get('id')} references input source {input_source_id}, but agentguard.json input_sources does not define it.",
                    exact_export="Add the input source id, trust level, and description; include whether it is user-controlled, trusted automation, webhook, ticket, prompt, file upload, or scheduled job.",
                    command="Edit agent-evidence/agentguard.json, then run agentguard-graph validate --evidence-dir agent-evidence/ --json",
                )
        for memory_id in agent.get("memory", []):
            if memory_id not in memory_ids:
                _add_recommendation(
                    recommendations,
                    priority="P1",
                    kind="memory_reference",
                    file="agentguard.json",
                    target=str(memory_id),
                    reason=f"Agent {agent.get('id')} references memory store {memory_id}, but agentguard.json memory_stores does not define it.",
                    exact_export="Add the memory store id, persistence, sensitivity, data_classes, owner, retention_policy, and deletion workflow.",
                    command="Edit agent-evidence/agentguard.json, then run agentguard-graph validate --evidence-dir agent-evidence/ --json",
                )
        approval_policy_id = agent.get("approval_policy")
        if approval_policy_id and approval_policy_id not in policy_ids:
            _add_recommendation(
                recommendations,
                priority="P1",
                kind="approval_controls",
                file="approval-policy.json",
                target=str(approval_policy_id),
                reason=f"Agent {agent.get('id')} references approval policy {approval_policy_id}, but approval-policy.json does not define it.",
                exact_export="Add the approval policy id and rules for sensitive tool calls, approvals, denials, sandbox controls, egress limits, DLP controls, and audit requirements.",
                command="Edit agent-evidence/approval-policy.json, then run agentguard-graph validate --evidence-dir agent-evidence/ --json",
            )

    if not tools:
        _add_recommendation(
            recommendations,
            priority="P0",
            kind="tool_manifest",
            file="mcp-servers.json or openapi/",
            target="tools",
            reason="No MCP or OpenAPI tool evidence was provided.",
            exact_export="Export MCP tool descriptors, code-adjacent tool manifests, or OpenAPI JSON files for every tool the agent can call.",
            command="agentguard-graph collect --project-dir . --out agent-evidence/ --mcp-config path/to/mcp-config.json --openapi path/to/openapi.json",
        )
    target_systems = sorted(
        {
            str(tool.get("target_system"))
            for tool in tools
            if tool.get("target_system") and tool.get("target_system") != "unknown"
        }
    )
    for identity in identities:
        if identity.get("target_system") and not identity.get("permissions") and not identity.get("scopes"):
            _add_target_export(
                recommendations,
                priority="P0",
                target=str(identity.get("target_system")),
                reason=f"Identity {identity.get('id')} has target_system={identity.get('target_system')} but no permissions or scopes.",
            )
    for gap in visibility_gaps:
        if gap.get("type") in {"unknown_target_iam_gap", "target_system_permissions_unknown", "identity_unknown"}:
            target = _target_from_gap(gap)
            _add_target_export(recommendations, priority="P0", target=target, reason=str(gap.get("reason", "")))
        if gap.get("type") in {"approval_policy_gap"}:
            _add_recommendation(
                recommendations,
                priority="P1",
                kind="approval_controls",
                file="approval-policy.json",
                target=str(gap.get("target", "approval-policy")),
                reason=str(gap.get("reason", "Approval policy evidence is incomplete.")),
                exact_export="Export or write approval, deny, sandbox, egress, DLP, command allowlist, and change-ticket controls for sensitive tools.",
                command="Edit agent-evidence/approval-policy.json, then run agentguard-graph doctor --evidence-dir agent-evidence/",
            )
    if target_systems and not data_sources:
        _add_recommendation(
            recommendations,
            priority="P1",
            kind="data_classification",
            file="data-catalog.json",
            target=", ".join(target_systems),
            reason="Tool target systems are known, but no data classification evidence was provided.",
            exact_export="Export data catalog, CMDB, privacy inventory, table/object classification, or manual resource classifications for these target systems.",
            command="Edit agent-evidence/data-catalog.json, then run agentguard-graph scan --evidence-dir agent-evidence/ --out outputs/agent-risk.json",
        )
    sensitive_or_dangerous = [
        tool
        for tool in tools
        if set(tool.get("risk_tags", [])).intersection(DANGEROUS_TAGS | {"financial_action", "external_message", "sensitive_read"})
    ]
    if sensitive_or_dangerous and (not policies or all(not policy.get("rules") for policy in policies)):
        _add_recommendation(
            recommendations,
            priority="P1",
            kind="approval_controls",
            file="approval-policy.json",
            target="sensitive tools",
            reason="Sensitive or dangerous tools exist, but approval/deny/control rules are missing.",
            exact_export="Export human approval rules, deny policies, sandbox controls, egress allowlists, command allowlists, DLP controls, and audit requirements.",
            command="Edit agent-evidence/approval-policy.json, then run agentguard-graph validate --evidence-dir agent-evidence/ --json",
        )
    if not input_sources and agents:
        _add_recommendation(
            recommendations,
            priority="P1",
            kind="input_sources",
            file="agentguard.json",
            target="input_sources",
            reason="Agents are declared, but no input source trust evidence was provided.",
            exact_export="List user-controlled and trusted input sources such as tickets, PR comments, Slack messages, webhooks, uploaded documents, and scheduled jobs.",
            command="Edit agent-evidence/agentguard.json, then run agentguard-graph validate --evidence-dir agent-evidence/ --json",
        )
    for memory in memory_stores:
        sensitive = set(memory.get("data_classes", [])).intersection(SENSITIVE_DATA_CLASSES)
        if memory.get("persistence") == "persistent" and sensitive and memory.get("retention_policy") in {"", "unknown"}:
            _add_recommendation(
                recommendations,
                priority="P1",
                kind="memory_retention",
                file="agentguard.json",
                target=str(memory.get("id", "memory_store")),
                reason=f"Persistent memory contains {', '.join(sorted(sensitive))} but has no retention policy.",
                exact_export="Add retention, redaction, deletion workflow, and memory-write control evidence for this memory store.",
                command="Edit agent-evidence/agentguard.json, then run agentguard-graph doctor --evidence-dir agent-evidence/",
            )
    if not events:
        _add_recommendation(
            recommendations,
            priority="P2",
            kind="runtime_events",
            file="events.jsonl",
            target="runtime telemetry",
            reason="No runtime events were provided; findings will remain static or supported rather than observed.",
            exact_export="Export redacted tool-call, approval, allow, block, memory, external-send, and session-correlation events as JSONL.",
            command="Export events.jsonl, then run agentguard-graph scan --evidence-dir agent-evidence/ --out outputs/agent-risk.json",
        )
    for warning in validation.warnings:
        if "references unknown tool" in warning:
            target = warning.rsplit(":", 1)[-1].strip()
            _add_recommendation(
                recommendations,
                priority="P0",
                kind="tool_descriptor",
                file="mcp-servers.json or openapi/",
                target=target,
                reason=warning,
                exact_export="Export MCP descriptor or OpenAPI operation evidence for this exact tool id.",
                command="agentguard-graph collect --project-dir . --out agent-evidence/",
            )
    return sorted(
        recommendations,
        key=lambda item: (EXPORT_PRIORITY_ORDER.get(item["priority"], 9), item["kind"], item["target"]),
    )


def _add_recommendation(
    recommendations: list[dict[str, Any]],
    *,
    priority: str,
    kind: str,
    file: str,
    target: str,
    reason: str,
    exact_export: str,
    command: str,
) -> None:
    key = (priority, kind, file, target, exact_export)
    existing = {
        (item["priority"], item["kind"], item["file"], item["target"], item["exact_export"])
        for item in recommendations
    }
    if key in existing:
        return
    recommendations.append(
        {
            "priority": priority,
            "kind": kind,
            "file": file,
            "target": target,
            "reason": reason,
            "exact_export": exact_export,
            "command": command,
        }
    )


def _add_target_export(recommendations: list[dict[str, Any]], *, priority: str, target: str, reason: str) -> None:
    hint = TARGET_EXPORT_HINTS.get(target)
    if not hint:
        _add_recommendation(
            recommendations,
            priority=priority,
            kind="identity_permissions",
            file="identity.json",
            target=target or "unknown",
            reason=reason,
            exact_export="Export or write the target-system identity permissions, scopes, and resource access used by the agent.",
            command="Edit agent-evidence/identity.json, then run agentguard-graph validate --evidence-dir agent-evidence/ --json",
        )
        return
    _add_recommendation(
        recommendations,
        priority=priority,
        kind="identity_permissions",
        file=hint["file"],
        target=target,
        reason=reason,
        exact_export=hint["exact_export"],
        command=f"agentguard-graph collect --out agent-evidence/ {hint['flag']}",
    )


def _target_from_gap(gap: dict[str, Any]) -> str:
    target = str(gap.get("target", ""))
    if ":" in target:
        tail = target.split(":")[-1]
        if tail in TARGET_EXPORT_HINTS:
            return tail
    for candidate in TARGET_EXPORT_HINTS:
        if candidate in target or candidate in str(gap.get("reason", "")).lower():
            return candidate
    return infer_target_system(target)


def _project_discovery(project_dir: str | None, discovered_inputs: dict[str, list[str]] | None) -> dict[str, Any] | None:
    if not project_dir:
        return None
    discovered_inputs = discovered_inputs or {}
    found = {kind: paths for kind, paths in discovered_inputs.items() if paths}
    missing_key_sources = [
        kind
        for kind in ["mcp_config", "openapi", "tool_manifest", "github_app_export", "oauth_scopes_export", "aws_iam_policy"]
        if not discovered_inputs.get(kind)
    ]
    command = f"agentguard-graph collect --project-dir {project_dir} --out agent-evidence/"
    return {
        "project_dir": project_dir,
        "found": found,
        "missing_common_sources": missing_key_sources,
        "recommended_collect_command": command,
    }


def _next_commands(
    evidence_dir: str | None,
    evidence_paths: dict[str, str],
    project_discovery: dict[str, Any] | None,
    package_ready: bool,
    recommended_exports: list[dict[str, Any]],
) -> list[str]:
    evidence_ref = evidence_dir or _first_parent(evidence_paths) or "agent-evidence/"
    commands: list[str] = []
    if project_discovery and project_discovery.get("recommended_collect_command"):
        commands.append(project_discovery["recommended_collect_command"])
    commands.append(f"agentguard-graph doctor --evidence-dir {evidence_ref}")
    if package_ready and (evidence_dir or _first_parent(evidence_paths)):
        commands.append(f"Compress-Archive -Path {evidence_ref} -DestinationPath agent-evidence.zip")
    if recommended_exports:
        commands.extend(item["command"] for item in recommended_exports[:3] if item.get("command"))
    return _unique_strings(commands)


def _first_parent(evidence_paths: dict[str, str]) -> str:
    for value in evidence_paths.values():
        if value:
            path = Path(value)
            return str(path if path.is_dir() else path.parent)
    return ""


def _top_visibility_gaps(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        gaps,
        key=lambda gap: (GAP_PRIORITY_ORDER.get(str(gap.get("priority")), 9), str(gap.get("id", ""))),
    )[:8]


def _status(
    validation: ValidationResult,
    secret_findings: list[dict[str, Any]],
    recommended_exports: list[dict[str, Any]],
) -> str:
    if secret_findings:
        return "blocked_by_secrets"
    if validation.errors:
        return "invalid_evidence"
    if any(item["priority"] in {"P0", "P1"} for item in recommended_exports):
        return "needs_evidence"
    if recommended_exports:
        return "ready_with_followups"
    return "ready_for_handoff"


def _blockers(validation: ValidationResult, secret_findings: list[dict[str, Any]]) -> list[str]:
    blockers = []
    if secret_findings:
        blockers.append("Likely secret material is present in evidence files. Redact before packaging.")
    blockers.extend(validation.errors)
    return blockers


def _source_status(count: int, partial: bool = False) -> str:
    if count <= 0:
        return "missing"
    if partial:
        return "partial"
    return "present"


def _count_note(items: list[Any], label: str) -> str:
    return f"{len(items)} {label}" if items else ""


def _notes(parts: list[str]) -> str:
    return "; ".join(part for part in parts if part) or "complete enough for initial review"


def _unique_paths(paths: list[Path]) -> list[Path]:
    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        normalized = str(path)
        if normalized in seen:
            continue
        seen.add(normalized)
        unique.append(path)
    return unique


def _unique_strings(values: list[str]) -> list[str]:
    unique = []
    seen = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique
