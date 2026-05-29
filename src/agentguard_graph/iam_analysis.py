"""IAM binding coverage and least-privilege review helpers."""

from __future__ import annotations

from typing import Any

from .schemas import infer_target_system
from .validation.validate_inputs import all_tools


READ_TAGS = {"read_action", "sensitive_read", "filesystem_read", "memory_read", "secret_access"}
WRITE_TAGS = {
    "write_action",
    "sensitive_write",
    "filesystem_write",
    "memory_write",
    "external_message",
    "financial_action",
    "production_write",
    "infrastructure_write",
    "ci_cd_write",
    "repository_write",
    "code_write",
    "destructive_action",
}
EXECUTE_TAGS = {"command_execution", "network_access"}
BROAD_ACTIONS = {"*", "all", "admin", "administrator", "owner", "manage", "full_access", "fullaccess"}
BROAD_RESOURCES = {"*", "all", "global", "tenant", "organization", "subscription", "project", "cluster"}
READ_ACTION_HINTS = {"read", "get", "list", "view", "select", "download", "search", "lookup", "describe"}
WRITE_ACTION_HINTS = {
    "write",
    "create",
    "update",
    "edit",
    "delete",
    "remove",
    "send",
    "post",
    "apply",
    "merge",
    "approve",
    "deploy",
    "execute",
    "run",
    "admin",
    "manage",
}
EXECUTE_ACTION_HINTS = {"execute", "run", "invoke", "apply", "deploy", "command"}
TARGET_EXPORTS = {
    "github": {
        "owner": "IAM admin",
        "exact_export": "Export GitHub App repository and organization permissions.",
        "least_privilege": "Use repository-scoped GitHub App permissions; grant contents:read for reads, pull_requests:write for PRs, and avoid administration, secrets, actions, or organization write grants unless a tool requires them.",
    },
    "google_workspace": {
        "owner": "IAM admin",
        "exact_export": "Export Google Workspace OAuth scopes and delegated admin grants.",
        "least_privilege": "Use narrow OAuth scopes such as readonly scopes for search/read tools and send-only scopes for outbound mail; avoid broad Drive, Gmail, Admin SDK, or domain-wide delegation unless required.",
    },
    "slack": {
        "owner": "IAM admin",
        "exact_export": "Export Slack OAuth scopes and app-level permissions.",
        "least_privilege": "Use channel and message scopes that match the tool surface; avoid admin, users:read.email, channels:history, and workspace-wide scopes unless a tool requires them.",
    },
    "salesforce": {
        "owner": "IAM admin",
        "exact_export": "Export Salesforce connected app, profile, permission set, object, and field permissions.",
        "least_privilege": "Grant object and field permissions for the objects the tool uses; split read-only CRM lookup identities from create, edit, delete, or payment workflows.",
    },
    "aws": {
        "owner": "IAM admin",
        "exact_export": "Export the AWS IAM policy or role used by the agent.",
        "least_privilege": "Scope IAM actions to specific services and ARNs; avoid wildcard actions, wildcard resources, iam:*, secretsmanager:*, and broad write actions unless tied to a specific tool.",
    },
    "kubernetes": {
        "owner": "IAM admin",
        "exact_export": "Export Kubernetes Role or ClusterRole RBAC for the agent service account.",
        "least_privilege": "Prefer namespace-scoped Roles over ClusterRoles; grant get/list/watch for read tools and separate apply/delete privileges into an approval-gated identity.",
    },
    "microsoft_365": {
        "owner": "IAM admin",
        "exact_export": "Export Microsoft 365, Graph, Teams, SharePoint, mailbox, connector, and Copilot permissions.",
        "least_privilege": "Use read-only Graph scopes for search and context tools, send-only mail permissions for outbound mail, and avoid tenant-wide or Files.ReadWrite.All grants unless required.",
    },
    "azure": {
        "owner": "IAM admin",
        "exact_export": "Export Azure RBAC role assignments for the agent principal.",
        "least_privilege": "Prefer resource-group or resource-scoped roles; avoid Owner, Contributor, User Access Administrator, and wildcard data-plane grants unless required.",
    },
    "gcp": {
        "owner": "IAM admin",
        "exact_export": "Export Google Cloud IAM bindings for the agent service account.",
        "least_privilege": "Prefer predefined or custom roles scoped to the required project/resource; avoid Owner, Editor, Service Account Token Creator, and broad storage or secret-manager roles unless required.",
    },
    "okta": {
        "owner": "IAM admin",
        "exact_export": "Export Okta admin roles, app assignments, and OAuth scopes.",
        "least_privilege": "Use app-specific OAuth scopes and read-only admin roles where possible; avoid Super Admin, Org Admin, and broad user lifecycle privileges unless a tool requires them.",
    },
}


def build_iam_analysis(evidence: dict[str, Any]) -> dict[str, Any]:
    tools_by_id = {tool["id"]: tool for tool in all_tools(evidence) if tool.get("id")}
    identities_by_id = {
        identity["id"]: identity
        for identity in (evidence.get("identity") or {}).get("identities", [])
        if identity.get("id")
    }
    binding_coverage: list[dict[str, Any]] = []
    used_identities: set[str] = set()
    ambiguous_identities: set[str] = set()
    explained_permissions: set[str] = set()
    least_privilege_suggestions: list[dict[str, Any]] = []

    for agent in (evidence.get("agents") or {}).get("agents", []):
        for tool_id in agent.get("tools", []):
            tool = tools_by_id.get(tool_id, {})
            coverage = _coverage_for_tool(agent, tool_id, tool, identities_by_id)
            binding_coverage.append(coverage)
            if coverage["binding_type"] in {"explicit", "inferred"}:
                used_identities.update(coverage["selected_identities"])
            elif coverage["binding_type"] == "ambiguous":
                ambiguous_identities.update(coverage["ambiguous_same_target_identities"])
                least_privilege_suggestions.append(_binding_suggestion(coverage))
            if coverage.get("permission_status") in {"missing", "weak"}:
                least_privilege_suggestions.append(_missing_permission_suggestion(coverage))
            for permission in coverage.get("supporting_permissions", []):
                explained_permissions.add(permission["permission_id"])
            for suggestion in _broad_permission_suggestions(coverage):
                least_privilege_suggestions.append(suggestion)

    unused_identities = _unused_identities(identities_by_id, binding_coverage, used_identities, ambiguous_identities)
    unused_permissions = _unused_permissions(identities_by_id, binding_coverage, explained_permissions)
    least_privilege_suggestions.extend(_unused_permission_suggestions(unused_permissions))
    least_privilege_suggestions = _dedupe_suggestions(least_privilege_suggestions)
    return {
        "summary": {
            "agent_tool_bindings": len(binding_coverage),
            "explicit_bindings": sum(1 for item in binding_coverage if item["binding_type"] == "explicit"),
            "inferred_bindings": sum(1 for item in binding_coverage if item["binding_type"] == "inferred"),
            "ambiguous_bindings": sum(1 for item in binding_coverage if item["binding_type"] == "ambiguous"),
            "unbound_tools": sum(1 for item in binding_coverage if item["binding_type"] in {"unbound", "unknown_target"}),
            "unused_identities": len(unused_identities),
            "unused_permissions": len(unused_permissions),
            "least_privilege_suggestions": len(least_privilege_suggestions),
        },
        "binding_coverage": binding_coverage,
        "unused_identities": unused_identities,
        "unused_permissions": unused_permissions,
        "least_privilege_suggestions": least_privilege_suggestions,
    }


def _coverage_for_tool(
    agent: dict[str, Any],
    tool_id: str,
    tool: dict[str, Any],
    identities_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    target_system = str(tool.get("target_system") or infer_target_system(tool_id) or "unknown")
    explicit_identities = _bound_identity_ids(agent, tool_id)
    agent_identity_ids = _agent_identity_ids(agent)
    same_target_identity_ids = [
        identity_id
        for identity_id in agent_identity_ids
        if (identity := identities_by_id.get(identity_id)) and identity.get("target_system") == target_system
    ]
    required_actions = _required_actions(tool)
    if explicit_identities:
        binding_type = "explicit"
        selected_identities = explicit_identities
        reason = "Tool has an explicit tool_identity_bindings entry."
    elif target_system == "unknown":
        binding_type = "unknown_target"
        selected_identities = []
        reason = "Tool target system is unknown, so identity matching cannot be inferred."
    elif len(same_target_identity_ids) == 1:
        binding_type = "inferred"
        selected_identities = same_target_identity_ids
        reason = "One declared agent identity has the same target system as the tool."
    elif len(same_target_identity_ids) > 1:
        binding_type = "ambiguous"
        selected_identities = []
        reason = "Multiple declared agent identities share this tool target system; add an explicit binding."
    else:
        binding_type = "unbound"
        selected_identities = []
        reason = "No declared agent identity matches this tool target system."
    candidate_identities = explicit_identities or same_target_identity_ids
    supporting_permissions, broad_permissions = _supporting_permissions(
        selected_identities if selected_identities else candidate_identities,
        tool,
        required_actions,
        identities_by_id,
    )
    missing_permission_evidence = any(
        identities_by_id.get(identity_id, {}).get("target_system") == target_system
        and not identities_by_id.get(identity_id, {}).get("permissions")
        for identity_id in candidate_identities
    )
    if supporting_permissions:
        permission_status = "supported"
    elif missing_permission_evidence or not candidate_identities:
        permission_status = "missing"
    else:
        permission_status = "weak"
    return {
        "agent": str(agent.get("id", "")),
        "tool": tool_id,
        "target_system": target_system,
        "risk_tags": tool.get("risk_tags", []),
        "required_actions": required_actions,
        "binding_type": binding_type,
        "explicit_identities": explicit_identities,
        "inferred_identities": same_target_identity_ids if binding_type in {"inferred", "ambiguous"} else [],
        "candidate_identities": candidate_identities,
        "selected_identities": selected_identities,
        "ambiguous_same_target_identities": same_target_identity_ids if binding_type == "ambiguous" else [],
        "permission_status": permission_status,
        "supporting_permissions": supporting_permissions,
        "broad_permissions": broad_permissions,
        "reason": reason,
        "recommended_action": _coverage_recommendation(binding_type, target_system, tool_id, permission_status),
    }


def _bound_identity_ids(agent: dict[str, Any], tool_id: str) -> list[str]:
    return _ordered_unique(
        [
            str(binding.get("identity"))
            for binding in agent.get("tool_identity_bindings", [])
            if isinstance(binding, dict) and binding.get("tool") == tool_id and binding.get("identity")
        ]
    )


def _agent_identity_ids(agent: dict[str, Any]) -> list[str]:
    identities = [str(identity_id) for identity_id in agent.get("identities", []) if identity_id]
    identities.extend(
        str(binding.get("identity"))
        for binding in agent.get("tool_identity_bindings", [])
        if isinstance(binding, dict) and binding.get("identity")
    )
    return _ordered_unique(identities)


def _ordered_unique(values: list[str]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            ordered.append(value)
            seen.add(value)
    return ordered


def _required_actions(tool: dict[str, Any]) -> list[str]:
    tags = set(tool.get("risk_tags", []))
    required: list[str] = []
    if tags.intersection(READ_TAGS):
        required.append("read")
    if tags.intersection(WRITE_TAGS):
        required.append("write")
    if "external_message" in tags:
        required.append("send")
    if tags.intersection(EXECUTE_TAGS):
        required.append("execute")
    if not required:
        required.append("read")
    return _ordered_unique(required)


def _supporting_permissions(
    identity_ids: list[str],
    tool: dict[str, Any],
    required_actions: list[str],
    identities_by_id: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    supporting: list[dict[str, Any]] = []
    broad: list[dict[str, Any]] = []
    for identity_id in identity_ids:
        identity = identities_by_id.get(identity_id, {})
        for index, permission in enumerate(identity.get("permissions", []), start=1):
            permission_id = _permission_id(identity_id, index, permission)
            summary = _permission_summary(identity_id, index, permission, permission_id)
            if _permission_supports_tool(permission, tool, required_actions):
                supporting.append(summary)
            if _permission_is_broad(permission):
                broad.append(summary)
    return supporting, broad


def _permission_supports_tool(permission: dict[str, Any], tool: dict[str, Any], required_actions: list[str]) -> bool:
    actions = _normalized_actions(permission)
    if actions.intersection(BROAD_ACTIONS):
        return True
    resource_supported = _resource_supports_tool(permission, tool)
    if "read" in required_actions and actions.intersection(READ_ACTION_HINTS) and resource_supported:
        return True
    if any(action in required_actions for action in ["write", "send"]) and actions.intersection(WRITE_ACTION_HINTS) and resource_supported:
        return True
    if "execute" in required_actions and actions.intersection(EXECUTE_ACTION_HINTS | WRITE_ACTION_HINTS) and resource_supported:
        return True
    permission_classes = set(permission.get("data_classes", []))
    tool_classes = set(tool.get("data_classes", []) + tool.get("request_data_classes", []) + tool.get("response_data_classes", []))
    if permission_classes and tool_classes and permission_classes.intersection(tool_classes):
        return True
    return False


def _resource_supports_tool(permission: dict[str, Any], tool: dict[str, Any]) -> bool:
    resource = str(permission.get("resource", "")).lower()
    if not resource or resource == "unknown" or resource in BROAD_RESOURCES:
        return True
    tool_id = str(tool.get("id") or tool.get("name") or "").lower()
    normalized_resource = resource.replace("-", "_").replace(" ", "_")
    normalized_tool = tool_id.replace("-", "_").replace(".", "_")
    if normalized_resource in normalized_tool or normalized_resource.rstrip("s") in normalized_tool:
        return True
    tags = set(tool.get("risk_tags", []))
    resource_terms = set(normalized_resource.replace(":", "_").split("_"))
    if "repository_write" in tags and resource_terms.intersection({"repo", "repository", "pull", "pulls", "pr", "prs", "contents", "branch", "commit"}):
        return True
    if "external_message" in tags and resource_terms.intersection({"mail", "email", "message", "messages", "chat", "channel", "channels"}):
        return True
    if "sensitive_read" in tags and resource_terms.intersection({"contact", "contacts", "customer", "case", "account", "user", "users"}):
        return True
    if tags.intersection({"production_write", "infrastructure_write", "ci_cd_write"}) and resource_terms.intersection(
        {"deploy", "deployment", "cluster", "namespace", "workflow", "pipeline", "infrastructure"}
    ):
        return True
    return False


def _normalized_actions(permission: dict[str, Any]) -> set[str]:
    values = []
    values.extend(str(action) for action in permission.get("actions", []) if action is not None)
    scope = permission.get("scope")
    if scope:
        values.append(str(scope))
    values.extend(str(scope) for scope in permission.get("scopes", []) if scope is not None)
    normalized: set[str] = set()
    for value in values:
        for part in value.replace(":", " ").replace(".", " ").replace("_", " ").replace("-", " ").split():
            if part:
                normalized.add(part.lower())
        if value:
            normalized.add(value.lower())
    return normalized


def _permission_is_broad(permission: dict[str, Any]) -> bool:
    actions = _normalized_actions(permission)
    resource = str(permission.get("resource", "")).strip().lower()
    return bool(actions.intersection(BROAD_ACTIONS) or resource in BROAD_RESOURCES or any(action.endswith(":*") for action in actions))


def _permission_summary(identity_id: str, index: int, permission: dict[str, Any], permission_id: str) -> dict[str, Any]:
    return {
        "permission_id": permission_id,
        "identity": identity_id,
        "resource": str(permission.get("resource", "")),
        "actions": [str(action) for action in permission.get("actions", [])],
        "data_classes": [str(data_class) for data_class in permission.get("data_classes", [])],
        "confidence": str(permission.get("confidence", "medium")),
        "index": index,
    }


def _permission_id(identity_id: str, index: int, permission: dict[str, Any]) -> str:
    resource = str(permission.get("resource", "resource")).replace(" ", "_")
    actions = "_".join(str(action).replace(" ", "_") for action in permission.get("actions", [])) or "actions"
    return f"{identity_id}#{index}:{resource}:{actions}"


def _coverage_recommendation(binding_type: str, target_system: str, tool_id: str, permission_status: str) -> str:
    if binding_type == "ambiguous":
        return f"Add tool_identity_bindings for {tool_id} so reviewers know which {target_system} identity is used."
    if binding_type in {"unbound", "unknown_target"}:
        return f"Add or export the identity used by {tool_id}, including target_system, permissions, and scopes."
    if permission_status in {"missing", "weak"}:
        return _target_guidance(target_system)["exact_export"]
    return "Binding and permission evidence are present; review least-privilege suggestions for overbroad grants."


def _unused_identities(
    identities_by_id: dict[str, dict[str, Any]],
    coverage: list[dict[str, Any]],
    used_identities: set[str],
    ambiguous_identities: set[str],
) -> list[dict[str, Any]]:
    agent_identity_ids = {
        identity_id
        for item in coverage
        for identity_id in item.get("candidate_identities", []) + item.get("selected_identities", [])
    }
    unused = []
    for identity_id, identity in sorted(identities_by_id.items()):
        if identity_id in used_identities or identity_id in ambiguous_identities:
            continue
        if identity_id in agent_identity_ids:
            reason = "Identity is declared on an agent but no covered tool proves it is required."
        else:
            reason = "Identity is present in identity.json but is not referenced by any agent or tool binding."
        unused.append(
            {
                "identity": identity_id,
                "target_system": str(identity.get("target_system", "unknown")),
                "permissions": len(identity.get("permissions", [])),
                "scopes": identity.get("scopes", []),
                "reason": reason,
                "recommended_action": "Remove the identity from the evidence pack or add an explicit tool binding and supporting runtime evidence.",
            }
        )
    return unused


def _unused_permissions(
    identities_by_id: dict[str, dict[str, Any]],
    coverage: list[dict[str, Any]],
    explained_permissions: set[str],
) -> list[dict[str, Any]]:
    identity_targets = {
        item.get("selected_identities", [None])[0]: item.get("target_system")
        for item in coverage
        if item.get("selected_identities")
    }
    unused = []
    for identity_id, identity in sorted(identities_by_id.items()):
        for index, permission in enumerate(identity.get("permissions", []), start=1):
            permission_id = _permission_id(identity_id, index, permission)
            if permission_id in explained_permissions:
                continue
            reason = "No covered tool currently requires this resource/action grant."
            if identity_id not in identity_targets:
                reason = "No covered tool is bound or inferred to use this identity."
            item = _permission_summary(identity_id, index, permission, permission_id)
            item.update(
                {
                    "target_system": str(identity.get("target_system", "unknown")),
                    "reason": reason,
                    "recommended_action": "Remove the grant, split it into a separate approved identity, or add evidence that maps it to a specific tool.",
                }
            )
            unused.append(item)
    return unused


def _binding_suggestion(coverage: dict[str, Any]) -> dict[str, Any]:
    return {
        "priority": "P0",
        "target_system": coverage["target_system"],
        "agent": coverage["agent"],
        "tool": coverage["tool"],
        "identity": "",
        "reason": "Multiple same-target identities can satisfy this tool, so the effective credential is ambiguous.",
        "suggestion": f"Add tool_identity_bindings for {coverage['tool']} to exactly one of {', '.join(coverage['ambiguous_same_target_identities'])}.",
    }


def _missing_permission_suggestion(coverage: dict[str, Any]) -> dict[str, Any]:
    guidance = _target_guidance(coverage["target_system"])
    return {
        "priority": "P0" if coverage["binding_type"] in {"unbound", "ambiguous"} else "P1",
        "target_system": coverage["target_system"],
        "agent": coverage["agent"],
        "tool": coverage["tool"],
        "identity": ", ".join(coverage.get("candidate_identities", [])),
        "reason": "Binding exists or is inferable, but target-system permissions are missing or too weak to prove least privilege.",
        "suggestion": f"{guidance['exact_export']} {guidance['least_privilege']}",
    }


def _broad_permission_suggestions(coverage: dict[str, Any]) -> list[dict[str, Any]]:
    guidance = _target_guidance(coverage["target_system"])
    suggestions = []
    for permission in coverage.get("broad_permissions", []):
        suggestions.append(
            {
                "priority": "P1",
                "target_system": coverage["target_system"],
                "agent": coverage["agent"],
                "tool": coverage["tool"],
                "identity": permission["identity"],
                "permission_id": permission["permission_id"],
                "reason": "A broad grant is attached to an identity that may be used by this tool.",
                "suggestion": guidance["least_privilege"],
            }
        )
    return suggestions


def _unused_permission_suggestions(unused_permissions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    suggestions = []
    for permission in unused_permissions:
        guidance = _target_guidance(permission["target_system"])
        suggestions.append(
            {
                "priority": "P2",
                "target_system": permission["target_system"],
                "agent": "",
                "tool": "",
                "identity": permission["identity"],
                "permission_id": permission["permission_id"],
                "reason": permission["reason"],
                "suggestion": f"Remove or justify unused grant {permission['resource']} {', '.join(permission['actions'])}. {guidance['least_privilege']}",
            }
        )
    return suggestions


def _target_guidance(target_system: str) -> dict[str, str]:
    return TARGET_EXPORTS.get(
        target_system,
        {
            "owner": "IAM admin",
            "exact_export": "Export target-system permissions, scopes, roles, grants, and resource access.",
            "least_privilege": "Scope the identity to the specific resources and actions required by bound tools.",
        },
    )


def _dedupe_suggestions(suggestions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    priority_order = {"P0": 0, "P1": 1, "P2": 2}
    for suggestion in sorted(
        suggestions,
        key=lambda item: (
            priority_order.get(str(item.get("priority", "P2")), 9),
            str(item.get("target_system", "")),
            str(item.get("agent", "")),
            str(item.get("tool", "")),
            str(item.get("identity", "")),
        ),
    ):
        key = (
            str(suggestion.get("priority", "")),
            str(suggestion.get("target_system", "")),
            str(suggestion.get("tool", "")),
            str(suggestion.get("identity", "")),
            str(suggestion.get("permission_id", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(suggestion)
    return deduped
