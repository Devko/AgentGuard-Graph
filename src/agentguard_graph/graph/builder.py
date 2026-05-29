"""Build the normalized Agent Security Graph."""

from __future__ import annotations

from typing import Any

from ..models import Edge, Graph, Node, VisibilityGap
from ..schemas import (
    DANGEROUS_TAGS,
    SENSITIVE_DATA_CLASSES,
    edge_id,
    infer_target_system,
    node_id,
)
from ..validation.validate_inputs import all_tools
from ..adapters.approval_policy import evaluate_policy

IAM_VISIBILITY_TARGET_SYSTEMS = {
    "aws",
    "azure",
    "confluence",
    "databricks",
    "dataverse",
    "gcp",
    "github",
    "google_workspace",
    "jira",
    "kubernetes",
    "microsoft_365",
    "netsuite",
    "okta",
    "power_platform",
    "salesforce",
    "slack",
    "servicenow",
    "snowflake",
    "stripe",
    "zendesk",
}


def _tool_by_id(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {tool["id"]: tool for tool in all_tools(evidence) if tool.get("id")}


def _identity_by_id(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in evidence.get("identity", {}).get("identities", []) if item.get("id")}


def _data_by_id(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in evidence.get("data_catalog", {}).get("data_sources", []) if item.get("id")}


def _bound_identity_ids(agent: dict[str, Any], tool_id: str) -> list[str]:
    identities: list[str] = []
    for binding in agent.get("tool_identity_bindings", []):
        if isinstance(binding, dict) and binding.get("tool") == tool_id and binding.get("identity"):
            identities.append(str(binding["identity"]))
    return _ordered_unique(identities)


def _agent_identity_ids(agent: dict[str, Any]) -> list[str]:
    identities = list(agent.get("identities", []))
    identities.extend(str(binding["identity"]) for binding in agent.get("tool_identity_bindings", []) if isinstance(binding, dict) and binding.get("identity"))
    return _ordered_unique(identities)


def _ordered_unique(values: list[str]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            ordered.append(value)
            seen.add(value)
    return ordered


def _data_for_permission(permission: dict[str, Any], data_sources: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    resource = permission.get("resource", "")
    if resource in data_sources:
        return [data_sources[resource]]
    classes = set(permission.get("data_classes", []))
    if not classes:
        return []
    return [item for item in data_sources.values() if classes.intersection(item.get("data_classes", []))]


def _upsert_gap(gaps: dict[str, VisibilityGap], gap: VisibilityGap) -> None:
    gaps.setdefault(gap.id, gap)


def _matching_identities_for_tool(
    agent: dict[str, Any],
    identities_by_id: dict[str, dict[str, Any]],
    target_system: str,
    tool_id: str,
) -> list[dict[str, Any]]:
    identity_ids = _bound_identity_ids(agent, tool_id) or _agent_identity_ids(agent)
    return [
        identity
        for identity_id in identity_ids
        if (identity := identities_by_id.get(identity_id)) and identity.get("target_system") == target_system
    ]


def _tool_evidence_layer(tool: dict[str, Any]) -> str:
    if tool.get("method"):
        return "openapi_static"
    if tool.get("risk_source") == "inferred":
        return "mcp_inferred"
    return "mcp_static"


def _approval_node_id(policy_id: str) -> str:
    return node_id("approval_policy", policy_id or "unknown")


def _add_missing_evidence_edge(
    graph: Graph,
    *,
    from_node: str,
    to_node: str,
    source: str,
    gap_id: str,
    reason: str,
    requested_evidence: str,
) -> None:
    graph.add_edge(
        Edge(
            id=edge_id("missing_evidence", from_node, to_node),
            from_node=from_node,
            to_node=to_node,
            type="missing_evidence",
            label="missing evidence",
            properties={"reason": reason},
            source=source,
            confidence="high",
            evidence_layer="inferred_gap",
            unknowns=[reason],
            visibility_gaps=[gap_id],
            recommended_next_evidence=[requested_evidence],
        )
    )


def build_graph(evidence: dict[str, Any]) -> tuple[Graph, list[VisibilityGap]]:
    graph = Graph()
    gaps: dict[str, VisibilityGap] = {}
    tools_by_id = _tool_by_id(evidence)
    identities_by_id = _identity_by_id(evidence)
    data_by_id = _data_by_id(evidence)
    policies = evidence.get("approval_policy", {}).get("policies", [])

    for input_source in evidence.get("agents", {}).get("input_sources", []):
        graph.add_node(
            Node(
                id=node_id("input_source", input_source["id"]),
                type="input_source",
                label=input_source.get("id", ""),
                properties={"trust": input_source.get("trust"), "description": input_source.get("description")},
                source=input_source.get("source_file", "unknown"),
                confidence="high",
                evidence_layer="agent_config",
            )
        )

    for memory in evidence.get("agents", {}).get("memory_stores", []):
        memory_gap_ids: list[str] = []
        memory_next_evidence: list[str] = []
        memory_sensitive = set(memory.get("data_classes", [])).intersection(SENSITIVE_DATA_CLASSES)
        if memory.get("persistence") == "persistent" and memory_sensitive and memory.get("retention_policy") in {"", "unknown"}:
            gap = VisibilityGap(
                id=f"gap-memory-retention-{memory['id']}",
                type="memory_retention_policy_gap",
                target=memory["id"],
                reason=f"Persistent memory store {memory['id']} contains sensitive data but has no retention policy.",
                requested_evidence="Provide retention, redaction, deletion workflow, and memory-write control evidence.",
                severity="medium",
            )
            _upsert_gap(gaps, gap)
            memory_gap_ids.append(gap.id)
            memory_next_evidence.append(gap.requested_evidence)
        graph.add_node(
            Node(
                id=node_id("memory_store", memory["id"]),
                type="memory_store",
                label=memory.get("id", ""),
                properties={
                    "persistence": memory.get("persistence"),
                    "retention_policy": memory.get("retention_policy"),
                    "owner": memory.get("owner", ""),
                    "retention_period": memory.get("retention_period", ""),
                    "deletion_policy": memory.get("deletion_policy", ""),
                    "data_classes": memory.get("data_classes", []),
                    "source_evidence": memory.get("source_evidence", []),
                },
                source=memory.get("source_file", "unknown"),
                confidence="high",
                evidence_layer="agent_config",
                visibility_gaps=memory_gap_ids,
                recommended_next_evidence=memory_next_evidence,
            )
        )

    for data_source in data_by_id.values():
        graph.add_node(
            Node(
                id=node_id("data_source", data_source["id"]),
                type="data_source",
                label=data_source.get("name") or data_source["id"],
                properties={
                    "target_system": data_source.get("target_system"),
                    "data_classes": data_source.get("data_classes", []),
                    "sensitivity": data_source.get("sensitivity"),
                    "owner": data_source.get("owner", ""),
                    "classification_labels": data_source.get("classification_labels", []),
                    "fields": data_source.get("fields", []),
                    "source_kind": data_source.get("source_kind", ""),
                    "source_evidence": data_source.get("source_evidence", ""),
                },
                source=data_source.get("source_file", "unknown"),
                confidence="high",
                evidence_layer="data_catalog",
            )
        )

    for server in evidence.get("mcp", {}).get("servers", []):
        graph.add_node(
            Node(
                id=node_id("mcp_server", server["id"]),
                type="mcp_server",
                label=server.get("name") or server["id"],
                properties={"transport": server.get("transport"), "auth": server.get("auth")},
                source=server.get("source_file", "unknown"),
                confidence="high",
                evidence_layer="mcp_static",
            )
        )

    for tool in tools_by_id.values():
        tool_type = "api_operation" if tool.get("method") else "tool"
        tool_node = node_id("tool", tool["id"])
        graph.add_node(
            Node(
                id=tool_node,
                type=tool_type,
                label=tool.get("name") or tool["id"],
                properties={
                    "description": tool.get("description"),
                    "risk_tags": tool.get("risk_tags", []),
                    "risk_source": tool.get("risk_source"),
                    "target_system": tool.get("target_system"),
                    "method": tool.get("method"),
                    "path": tool.get("path"),
                    "security_scopes": tool.get("security_scopes", []),
                    "server_urls": tool.get("server_urls", []),
                    "api_document_id": tool.get("api_document_id"),
                    "api_source_id": tool.get("api_source_id"),
                    "api_title": tool.get("api_title"),
                    "api_version": tool.get("api_version"),
                    "request_data_classes": tool.get("request_data_classes", []),
                    "response_data_classes": tool.get("response_data_classes", []),
                    "data_classes": tool.get("data_classes", []),
                },
                source=tool.get("source_file", "unknown"),
                confidence=tool.get("risk_confidence", "medium"),
                evidence_layer=_tool_evidence_layer(tool),
                unknowns=["risk tags inferred from tool name/description/schema"] if tool.get("risk_source") == "inferred" else [],
                recommended_next_evidence=(
                    ["Provide explicit MCP risk_tags for this tool."]
                    if tool.get("risk_source") == "inferred"
                    else []
                ),
            )
        )
        if tool.get("method"):
            api_source = tool.get("api_source") if isinstance(tool.get("api_source"), dict) else {}
            api_source_value = (
                tool.get("api_document_id")
                or api_source.get("id")
                or tool.get("api_source_id")
                or f"api_source:{tool.get('source_file', 'unknown')}"
            )
            api_source_id = node_id("api_definition", str(api_source_value))
            api_title = tool.get("api_title") or api_source.get("title") or tool.get("source_file", "unknown")
            graph.add_node(
                Node(
                    id=api_source_id,
                    type="api_definition",
                    label=f"OpenAPI source {api_title}",
                    properties={
                        "kind": "api_definition",
                        "api_document_id": tool.get("api_document_id") or api_source.get("id"),
                        "api_source_id": tool.get("api_source_id"),
                        "title": api_title,
                        "version": tool.get("api_version") or api_source.get("version"),
                        "source_file": tool.get("source_file", "unknown"),
                        "server_urls": tool.get("server_urls", []),
                    },
                    source=tool.get("source_file", "unknown"),
                    confidence="high",
                    evidence_layer="openapi_static",
                )
            )
            graph.add_edge(
                Edge(
                    id=edge_id("api_defines_tool", api_source_id, tool_node),
                    from_node=api_source_id,
                    to_node=tool_node,
                    type="api_defines_tool",
                    label="defines API operation",
                    properties={
                        "api_document_id": tool.get("api_document_id") or api_source.get("id"),
                        "api_source_id": tool.get("api_source_id"),
                    },
                    source=tool.get("source_file", "unknown"),
                    confidence=tool.get("risk_confidence", "medium"),
                    evidence_layer="openapi_static",
                )
            )
        if tool.get("server_id"):
            graph.add_edge(
                Edge(
                    id=edge_id("tool_defined_by_mcp_server", node_id("mcp_server", tool["server_id"]), tool_node),
                    from_node=node_id("mcp_server", tool["server_id"]),
                    to_node=tool_node,
                    type="tool_defined_by_mcp_server",
                    label="defines",
                    source=tool.get("source_file", "unknown"),
                    confidence=tool.get("risk_confidence", "medium"),
                    evidence_layer="mcp_static",
                )
            )
        if "external_message" in tool.get("risk_tags", []) or "data_exfiltration_sink" in tool.get("risk_tags", []):
            sink_id = node_id("external_sink", f"{tool['id']}:external")
            graph.add_node(
                Node(
                    id=sink_id,
                    type="external_sink",
                    label="external recipient",
                    source=tool.get("source_file", "unknown"),
                    evidence_layer=_tool_evidence_layer(tool),
                )
            )
            graph.add_edge(
                Edge(
                    id=edge_id("tool_sends_external", tool_node, sink_id),
                    from_node=tool_node,
                    to_node=sink_id,
                    type="tool_sends_external",
                    label="sends external",
                    source=tool.get("source_file", "unknown"),
                    confidence=tool.get("risk_confidence", "medium"),
                    evidence_layer=_tool_evidence_layer(tool),
                )
            )
        if "command_execution" in tool.get("risk_tags", []):
            command_id = node_id("unknown", f"{tool['id']}:command_execution")
            graph.add_node(
                Node(
                    id=command_id,
                    type="unknown",
                    label="command execution",
                    properties={"risk_tag": "command_execution"},
                    source=tool.get("source_file", "unknown"),
                    confidence=tool.get("risk_confidence", "medium"),
                    evidence_layer=_tool_evidence_layer(tool),
                    unknowns=["Exact command surface is not described by current tool evidence."],
                    recommended_next_evidence=["Provide command allowlist, sandbox policy, and runtime command events."],
                )
            )
            graph.add_edge(
                Edge(
                    id=edge_id("tool_executes_command", tool_node, command_id),
                    from_node=tool_node,
                    to_node=command_id,
                    type="tool_executes_command",
                    label="executes command",
                    source=tool.get("source_file", "unknown"),
                    confidence=tool.get("risk_confidence", "medium"),
                    evidence_layer=_tool_evidence_layer(tool),
                    unknowns=["Exact command surface is not described by current tool evidence."],
                    recommended_next_evidence=["Provide command allowlist, sandbox policy, and runtime command events."],
                )
            )
        if set(tool.get("risk_tags", [])).intersection({"production_write", "infrastructure_write", "ci_cd_write", "repository_write"}):
            production_id = node_id("unknown", f"{tool['id']}:production_change")
            graph.add_node(
                Node(
                    id=production_id,
                    type="unknown",
                    label=f"{tool.get('target_system', 'production')} write surface",
                    properties={"risk_tags": tool.get("risk_tags", []), "target_system": tool.get("target_system", "unknown")},
                    source=tool.get("source_file", "unknown"),
                    confidence=tool.get("risk_confidence", "medium"),
                    evidence_layer=_tool_evidence_layer(tool),
                    unknowns=["Exact production write target is not fully described by current tool evidence."],
                    recommended_next_evidence=["Provide target-system permission export and change-control policy evidence."],
                )
            )
            graph.add_edge(
                Edge(
                    id=edge_id("tool_modifies_production", tool_node, production_id),
                    from_node=tool_node,
                    to_node=production_id,
                    type="tool_modifies_production",
                    label="modifies production-like system",
                    source=tool.get("source_file", "unknown"),
                    confidence=tool.get("risk_confidence", "medium"),
                    evidence_layer=_tool_evidence_layer(tool),
                    unknowns=["Exact production write target is not fully described by current tool evidence."],
                    recommended_next_evidence=["Provide target-system permission export and change-control policy evidence."],
                )
            )
        if "financial_action" in tool.get("risk_tags", []):
            financial_id = node_id("unknown", f"{tool['id']}:financial_action")
            graph.add_node(
                Node(
                    id=financial_id,
                    type="unknown",
                    label="financial action",
                    properties={"risk_tag": "financial_action", "target_system": tool.get("target_system", "unknown")},
                    source=tool.get("source_file", "unknown"),
                    confidence=tool.get("risk_confidence", "medium"),
                    evidence_layer=_tool_evidence_layer(tool),
                    unknowns=["Financial action amount, threshold, and approval context are not fully described."],
                    recommended_next_evidence=["Provide amount thresholds, financial approval policy, and audit events."],
                )
            )
            graph.add_edge(
                Edge(
                    id=edge_id("tool_writes_data", tool_node, financial_id),
                    from_node=tool_node,
                    to_node=financial_id,
                    type="tool_writes_data",
                    label="performs financial write",
                    properties={"risk_tags": tool.get("risk_tags", [])},
                    source=tool.get("source_file", "unknown"),
                    confidence=tool.get("risk_confidence", "medium"),
                    evidence_layer=_tool_evidence_layer(tool),
                    unknowns=["Financial action amount, threshold, and approval context are not fully described."],
                    recommended_next_evidence=["Provide amount thresholds, financial approval policy, and audit events."],
                )
            )
        for data_source in data_by_id.values():
            if tool.get("target_system") != data_source.get("target_system"):
                continue
            risk_tags = set(tool.get("risk_tags", []))
            data_node = node_id("data_source", data_source["id"])
            if risk_tags.intersection({"sensitive_read", "filesystem_read", "memory_read", "secret_access"}):
                graph.add_edge(
                    Edge(
                        id=edge_id("tool_reads_data", tool_node, data_node),
                        from_node=tool_node,
                        to_node=data_node,
                        type="tool_reads_data",
                        label="reads data",
                        properties={"risk_tags": tool.get("risk_tags", [])},
                        source=tool.get("source_file", "unknown"),
                        confidence=tool.get("risk_confidence", "medium"),
                        evidence_layer=_tool_evidence_layer(tool),
                    )
                )
            if risk_tags.intersection({"sensitive_write", "filesystem_write", "memory_write", "write_action", "code_write", "repository_write"}):
                graph.add_edge(
                    Edge(
                        id=edge_id("tool_writes_data", tool_node, data_node),
                        from_node=tool_node,
                        to_node=data_node,
                        type="tool_writes_data",
                        label="writes data",
                        properties={"risk_tags": tool.get("risk_tags", [])},
                        source=tool.get("source_file", "unknown"),
                        confidence=tool.get("risk_confidence", "medium"),
                        evidence_layer=_tool_evidence_layer(tool),
                    )
                )

    for identity in identities_by_id.values():
        identity_gap_ids: list[str] = []
        identity_next_evidence: list[str] = []
        if identity.get("target_system") and not identity.get("permissions"):
            gap = VisibilityGap(
                id=f"gap-iam-{identity['id']}",
                type="target_system_permissions_unknown",
                target=identity["id"],
                reason="Identity target system is declared but no permissions were provided.",
                requested_evidence="Provide OAuth scopes, service account policy, app permissions, or runtime audit export.",
                severity="medium",
            )
            _upsert_gap(gaps, gap)
            identity_gap_ids.append(gap.id)
            identity_next_evidence.append(gap.requested_evidence)
        graph.add_node(
            Node(
                id=node_id("identity", identity["id"]),
                type="identity",
                label=identity["id"],
                properties={
                    "identity_type": identity.get("type"),
                    "target_system": identity.get("target_system"),
                    "scopes": identity.get("scopes", []),
                },
                source=identity.get("source_file", "unknown"),
                confidence=identity.get("confidence", "medium"),
                evidence_layer="identity",
                visibility_gaps=identity_gap_ids,
                recommended_next_evidence=identity_next_evidence,
            )
        )
        for index, permission in enumerate(identity.get("permissions", []), start=1):
            permission_id = node_id("permission", f"{identity['id']}:{index}")
            graph.add_node(
                Node(
                    id=permission_id,
                    type="permission",
                    label=f"{permission.get('resource')} {','.join(permission.get('actions', []))}",
                    properties=permission,
                    source=identity.get("source_file", "unknown"),
                    confidence=permission.get("confidence", identity.get("confidence", "medium")),
                    evidence_layer="identity",
                )
            )
            graph.add_edge(
                Edge(
                    id=edge_id("identity_has_permission", node_id("identity", identity["id"]), permission_id),
                    from_node=node_id("identity", identity["id"]),
                    to_node=permission_id,
                    type="identity_has_permission",
                    label="has permission",
                    source=identity.get("source_file", "unknown"),
                    confidence=permission.get("confidence", "medium"),
                    evidence_layer="identity",
                )
            )
            for data_source in _data_for_permission(permission, data_by_id):
                graph.add_edge(
                    Edge(
                        id=edge_id("permission_reaches_data", permission_id, node_id("data_source", data_source["id"])),
                        from_node=permission_id,
                        to_node=node_id("data_source", data_source["id"]),
                        type="permission_reaches_data",
                        label="reaches data",
                        properties={"actions": permission.get("actions", [])},
                        source=identity.get("source_file", "unknown"),
                        confidence=permission.get("confidence", "medium"),
                        evidence_layer="identity",
                    )
                )

    for policy in policies:
        graph.add_node(
            Node(
                id=node_id("approval_policy", policy["id"]),
                type="approval_policy",
                label=policy["id"],
                properties={
                    "rules": [rule.get("id") for rule in policy.get("rules", [])],
                    "engine": policy.get("engine", ""),
                },
                source=policy.get("source_file", "unknown"),
                confidence="high",
                evidence_layer="policy",
            )
        )

    for agent in evidence.get("agents", {}).get("agents", []):
        agent_node = node_id("agent", agent["id"])
        agent_gap_ids: list[str] = []
        agent_next_evidence: list[str] = []
        if not agent.get("owner"):
            gap = VisibilityGap(
                id=f"gap-owner-{agent['id']}",
                type="owner_metadata_missing",
                target=agent["id"],
                reason=f"Agent {agent['id']} has no owner metadata.",
                requested_evidence="Add the responsible team or service owner to agentguard.json.",
                severity="low",
                priority="low_gap",
            )
            _upsert_gap(gaps, gap)
            agent_gap_ids.append(gap.id)
            agent_next_evidence.append(gap.requested_evidence)
        if agent.get("environment") in {"", "unknown", None}:
            gap = VisibilityGap(
                id=f"gap-environment-{agent['id']}",
                type="environment_unknown",
                target=agent["id"],
                reason=f"Agent {agent['id']} has unknown environment.",
                requested_evidence="Declare whether the agent runs in production, staging, development, local, or another governed environment.",
                severity="medium",
                priority="medium_gap",
            )
            _upsert_gap(gaps, gap)
            agent_gap_ids.append(gap.id)
            agent_next_evidence.append(gap.requested_evidence)
        graph.add_node(
            Node(
                id=agent_node,
                type="agent",
                label=agent.get("name") or agent["id"],
                properties={
                    "owner": agent.get("owner"),
                    "runtime": agent.get("runtime"),
                    "environment": agent.get("environment"),
                    "autonomy": agent.get("autonomy"),
                    "approval_policy": agent.get("approval_policy"),
                    "labels": agent.get("labels", {}),
                    "tool_identity_bindings": agent.get("tool_identity_bindings", []),
                },
                source=agent.get("source_file", "unknown"),
                confidence="high",
                evidence_layer="agent_config",
                visibility_gaps=agent_gap_ids,
                recommended_next_evidence=agent_next_evidence,
            )
        )
        policy_node = _approval_node_id(agent.get("approval_policy", "unknown"))
        if policy_node not in graph.nodes:
            graph.add_node(
                Node(
                    id=policy_node,
                    type="approval_policy",
                    label=agent.get("approval_policy") or "unknown approval policy",
                    properties={"missing": "approval_policy"},
                    source=agent.get("source_file", "unknown"),
                    confidence="low",
                    evidence_layer="inferred_gap",
                    unknowns=["approval policy evidence missing"],
                    recommended_next_evidence=["Provide approval-policy.json with matching policy and rules."],
                )
            )
        for input_source in agent.get("input_sources", []):
            input_node = node_id("input_source", input_source)
            missing_input = input_node not in graph.nodes
            if missing_input:
                gap = VisibilityGap(
                    id=f"gap-input-{agent['id']}-{input_source}",
                    type="input_source_unknown",
                    target=input_source,
                    reason=f"Agent {agent['id']} references an input source with no input source evidence.",
                    requested_evidence="Provide input source trust and description in agentguard.json.",
                    severity="medium",
                )
                _upsert_gap(gaps, gap)
                graph.add_node(
                    Node(
                        id=input_node,
                        type="unknown",
                        label=input_source,
                        properties={"missing": "input_source"},
                        source=agent.get("source_file", "unknown"),
                        confidence="low",
                        evidence_layer="inferred_gap",
                        unknowns=[gap.reason],
                        visibility_gaps=[gap.id],
                        recommended_next_evidence=[gap.requested_evidence],
                    )
                )
            graph.add_edge(
                Edge(
                    id=edge_id("agent_receives_input", input_node, agent_node),
                    from_node=input_node,
                    to_node=agent_node,
                    type="agent_receives_input",
                    label="receives input",
                    source=agent.get("source_file", "unknown"),
                    confidence="low" if missing_input else "high",
                    evidence_layer="agent_config" if not missing_input else "inferred_gap",
                    unknowns=["input_source evidence missing"] if missing_input else [],
                    visibility_gaps=[f"gap-input-{agent['id']}-{input_source}"] if missing_input else [],
                    recommended_next_evidence=(
                        ["Provide input source trust and description in agentguard.json."] if missing_input else []
                    ),
                )
            )
            if missing_input:
                _add_missing_evidence_edge(
                    graph,
                    from_node=agent_node,
                    to_node=input_node,
                    source=agent.get("source_file", "unknown"),
                    gap_id=f"gap-input-{agent['id']}-{input_source}",
                    reason="input_source evidence missing",
                    requested_evidence="Provide input source trust and description in agentguard.json.",
                )
        for memory in agent.get("memory", []):
            memory_node = node_id("memory_store", memory)
            missing_memory = memory_node not in graph.nodes
            if missing_memory:
                gap = VisibilityGap(
                    id=f"gap-memory-{agent['id']}-{memory}",
                    type="memory_store_unknown",
                    target=memory,
                    reason=f"Agent {agent['id']} references a memory store with no memory store evidence.",
                    requested_evidence="Provide memory store persistence, retention, and data class evidence.",
                    severity="medium",
                )
                _upsert_gap(gaps, gap)
                graph.add_node(
                    Node(
                        id=memory_node,
                        type="unknown",
                        label=memory,
                        properties={"missing": "memory_store"},
                        source=agent.get("source_file", "unknown"),
                        confidence="low",
                        evidence_layer="inferred_gap",
                        unknowns=[gap.reason],
                        visibility_gaps=[gap.id],
                        recommended_next_evidence=[gap.requested_evidence],
                    )
                )
            graph.add_edge(
                Edge(
                    id=edge_id("agent_has_memory", agent_node, memory_node),
                    from_node=agent_node,
                    to_node=memory_node,
                    type="agent_has_memory",
                    label="has memory",
                    source=agent.get("source_file", "unknown"),
                    confidence="low" if missing_memory else "high",
                    evidence_layer="agent_config" if not missing_memory else "inferred_gap",
                    unknowns=["memory store evidence missing"] if missing_memory else [],
                    visibility_gaps=[f"gap-memory-{agent['id']}-{memory}"] if missing_memory else [],
                    recommended_next_evidence=(
                        ["Provide memory store persistence, retention, and data class evidence."] if missing_memory else []
                    ),
                )
            )
            if missing_memory:
                _add_missing_evidence_edge(
                    graph,
                    from_node=agent_node,
                    to_node=memory_node,
                    source=agent.get("source_file", "unknown"),
                    gap_id=f"gap-memory-{agent['id']}-{memory}",
                    reason="memory store evidence missing",
                    requested_evidence="Provide memory store persistence, retention, and data class evidence.",
                )
        for identity_id in _agent_identity_ids(agent):
            identity_node = node_id("identity", identity_id)
            if identity_node not in graph.nodes:
                gap = VisibilityGap(
                    id=f"gap-identity-{agent['id']}-{identity_id}",
                    type="identity_unknown",
                    target=identity_id,
                    reason=f"Agent {agent['id']} references an identity with no identity evidence.",
                    requested_evidence="Provide identity evidence with target system, scopes, and permissions.",
                    severity="high",
                )
                _upsert_gap(gaps, gap)
                graph.add_node(
                    Node(
                        id=identity_node,
                        type="unknown",
                        label=identity_id,
                        properties={"missing": "identity"},
                        source=agent.get("source_file", "unknown"),
                        confidence="low",
                        evidence_layer="inferred_gap",
                        unknowns=[gap.reason],
                        visibility_gaps=[gap.id],
                        recommended_next_evidence=[gap.requested_evidence],
                    )
                )
            graph.add_edge(
                Edge(
                    id=edge_id("agent_runs_as_identity", agent_node, identity_node),
                    from_node=agent_node,
                    to_node=identity_node,
                    type="agent_runs_as_identity",
                    label="runs as",
                    source=agent.get("source_file", "unknown"),
                    confidence=identities_by_id.get(identity_id, {}).get("confidence", "low"),
                    evidence_layer="agent_config" if identity_id in identities_by_id else "inferred_gap",
                    unknowns=[] if identity_id in identities_by_id else ["identity evidence missing"],
                    visibility_gaps=[] if identity_id in identities_by_id else [f"gap-identity-{agent['id']}-{identity_id}"],
                    recommended_next_evidence=(
                        [] if identity_id in identities_by_id else ["Provide identity evidence with target system, scopes, and permissions."]
                    ),
                )
            )
            if identity_id not in identities_by_id:
                _add_missing_evidence_edge(
                    graph,
                    from_node=agent_node,
                    to_node=identity_node,
                    source=agent.get("source_file", "unknown"),
                    gap_id=f"gap-identity-{agent['id']}-{identity_id}",
                    reason="identity evidence missing",
                    requested_evidence="Provide identity evidence with target system, scopes, and permissions.",
                )
        for tool_id in agent.get("tools", []):
            tool = tools_by_id.get(tool_id)
            tool_node = node_id("tool", tool_id)
            if not tool:
                target_system = infer_target_system(tool_id)
                risk_tags: list[str] = []
                confidence = "low"
                gap = VisibilityGap(
                    id=f"gap-tool-{agent['id']}-{tool_id}",
                    type="tool_evidence_unknown",
                    target=tool_id,
                    reason=f"Agent {agent['id']} references a tool with no MCP/OpenAPI evidence.",
                    requested_evidence="Provide MCP descriptor or OpenAPI operation evidence for the tool.",
                    severity="medium",
                )
                _upsert_gap(gaps, gap)
                graph.add_node(
                    Node(
                        id=tool_node,
                        type="unknown",
                        label=tool_id,
                        properties={"missing": "tool"},
                        source=agent.get("source_file", "unknown"),
                        confidence="low",
                        evidence_layer="inferred_gap",
                        unknowns=[gap.reason],
                        visibility_gaps=[gap.id],
                        recommended_next_evidence=[gap.requested_evidence],
                    )
                )
            else:
                target_system = tool.get("target_system", "unknown")
                risk_tags = tool.get("risk_tags", [])
                confidence = tool.get("risk_confidence", "medium")
            graph.add_edge(
                Edge(
                    id=edge_id("agent_uses_tool", agent_node, tool_node),
                    from_node=agent_node,
                    to_node=tool_node,
                    type="agent_uses_tool",
                    label="uses tool",
                    source=agent.get("source_file", "unknown"),
                    confidence=confidence,
                    evidence_layer="agent_config" if tool else "inferred_gap",
                    unknowns=[] if tool else ["tool descriptor evidence missing"],
                    visibility_gaps=[] if tool else [f"gap-tool-{agent['id']}-{tool_id}"],
                    recommended_next_evidence=[] if tool else ["Provide MCP descriptor or OpenAPI operation evidence for the tool."],
                )
            )
            if not tool:
                _add_missing_evidence_edge(
                    graph,
                    from_node=agent_node,
                    to_node=tool_node,
                    source=agent.get("source_file", "unknown"),
                    gap_id=f"gap-tool-{agent['id']}-{tool_id}",
                    reason="tool descriptor evidence missing",
                    requested_evidence="Provide MCP descriptor or OpenAPI operation evidence for the tool.",
                )
            if target_system in IAM_VISIBILITY_TARGET_SYSTEMS:
                matching_identity = _matching_identities_for_tool(agent, identities_by_id, target_system, tool_id)
                if not matching_identity or any(not identity.get("permissions") for identity in matching_identity if identity):
                    gap = VisibilityGap(
                        id=f"gap-iam-{agent['id']}-{target_system}",
                        type="unknown_target_iam_gap",
                        target=f"{agent['id']}:{target_system}",
                        reason=f"Agent uses {target_system} tool {tool_id}, but matching identity permissions are missing or weak.",
                        requested_evidence=(
                            "Provide target-system permission export, OAuth scope export, service account policy, or runtime audit events."
                        ),
                        severity="high",
                    )
                    _upsert_gap(gaps, gap)
                    missing_iam_node = node_id("unknown", f"{agent['id']}:{target_system}:permissions")
                    graph.add_node(
                        Node(
                            id=missing_iam_node,
                            type="unknown",
                            label=f"{target_system} permissions unknown",
                            properties={"missing": "target_system_permissions", "target_system": target_system},
                            source=agent.get("source_file", "unknown"),
                            confidence="low",
                            evidence_layer="inferred_gap",
                            unknowns=[gap.reason],
                            visibility_gaps=[gap.id],
                            recommended_next_evidence=[gap.requested_evidence],
                        )
                    )
                    _add_missing_evidence_edge(
                        graph,
                        from_node=tool_node,
                        to_node=missing_iam_node,
                        source=agent.get("source_file", "unknown"),
                        gap_id=gap.id,
                        reason=gap.reason,
                        requested_evidence=gap.requested_evidence,
                    )
            for identity_id in _bound_identity_ids(agent, tool_id):
                identity_node = node_id("identity", identity_id)
                if identity_node not in graph.nodes:
                    continue
                graph.add_edge(
                    Edge(
                        id=edge_id("tool_bound_to_identity", tool_node, identity_node),
                        from_node=tool_node,
                        to_node=identity_node,
                        type="tool_bound_to_identity",
                        label="bound to identity",
                        properties={"tool": tool_id, "identity": identity_id},
                        source=agent.get("source_file", "unknown"),
                        confidence=identities_by_id.get(identity_id, {}).get("confidence", "medium"),
                        evidence_layer="agent_config",
                    )
                )
            context = {
                "agent": agent["id"],
                "tool": tool_id,
                "risk_tags": risk_tags,
                "action_class": risk_tags[0] if risk_tags else "",
                "target_system": target_system,
                "environment": agent.get("environment", "unknown"),
                "data_classes": [],
                "external_target": "external" if "external_message" in risk_tags else "",
            }
            policy_result = evaluate_policy(policies, agent.get("approval_policy", ""), context)
            if policy_result["decision"] == "approval_required":
                approval_type = "approval_present"
                label = "approval required"
            elif policy_result["decision"] == "deny":
                approval_type = "approval_present"
                label = "denied by policy"
            elif policy_result["decision"] == "allow":
                approval_type = "approval_present"
                label = "allowed by policy"
            elif set(risk_tags).intersection(DANGEROUS_TAGS | {"financial_action", "external_message"}):
                approval_type = "approval_missing"
                label = "approval missing or unknown"
                gap = VisibilityGap(
                    id=f"gap-approval-{agent['id']}-{tool_id}",
                    type="approval_policy_gap",
                    target=tool_id,
                    reason=f"No matching approval rule found for {tool_id}.",
                    requested_evidence="Add approval policy evidence for sensitive, financial, external, or dangerous actions.",
                    severity="high",
                )
                _upsert_gap(gaps, gap)
            else:
                approval_type = "approval_missing"
                label = "approval unknown"
            approval_gap_id = f"gap-approval-{agent['id']}-{tool_id}"
            approval_policy_node = _approval_node_id(agent.get("approval_policy", "unknown"))
            graph.add_edge(
                Edge(
                    id=edge_id(approval_type, tool_node, approval_policy_node),
                    from_node=tool_node,
                    to_node=approval_policy_node,
                    type=approval_type,
                    label=label,
                    properties=policy_result,
                    source=policy_result.get("source_file") or agent.get("source_file", "unknown"),
                    confidence="high" if policy_result.get("rule") else "medium",
                    evidence_layer="policy" if policy_result.get("rule") else "inferred_gap",
                    unknowns=[] if policy_result.get("rule") else ["no matching approval rule found"],
                    blockers=[label] if policy_result["decision"] in {"approval_required", "deny"} else [],
                    visibility_gaps=[approval_gap_id] if approval_type == "approval_missing" and label == "approval missing or unknown" else [],
                    recommended_next_evidence=(
                        ["Add approval policy evidence for sensitive, financial, external, or dangerous actions."]
                        if approval_type == "approval_missing" and label == "approval missing or unknown"
                        else []
                    ),
                )
            )
            if policy_result["decision"] == "approval_required":
                graph.add_edge(
                    Edge(
                        id=edge_id("action_requires_approval", tool_node, approval_policy_node),
                        from_node=tool_node,
                        to_node=approval_policy_node,
                        type="action_requires_approval",
                        label="requires approval",
                        properties=policy_result,
                        source=policy_result.get("source_file") or agent.get("source_file", "unknown"),
                        confidence="high",
                        evidence_layer="policy",
                        blockers=[policy_result.get("reason", "approval required")],
                    )
                )

    for event in evidence.get("events", {}).get("events", []):
        event_node = node_id("runtime_event", event["id"])
        edge_type = "event_blocked" if event.get("decision") in {"blocked", "deny", "denied"} else "event_allowed"
        graph.add_node(
            Node(
                id=event_node,
                type="runtime_event",
                label=f"{event.get('event_type')} {event.get('tool')}",
                properties=event,
                source=event.get("source_file", "unknown"),
                confidence=event.get("confidence", "medium"),
                evidence_layer="runtime",
            )
        )
        if event.get("agent"):
            graph.add_edge(
                Edge(
                    id=edge_id("event_observed", event_node, node_id("agent", event["agent"])),
                    from_node=event_node,
                    to_node=node_id("agent", event["agent"]),
                    type="event_observed",
                    label="observed runtime event",
                    source=event.get("source_file", "unknown"),
                    confidence=event.get("confidence", "medium"),
                    evidence_layer="runtime",
                )
            )
        if event.get("tool"):
            graph.add_edge(
                Edge(
                    id=edge_id(edge_type, event_node, node_id("tool", event["tool"])),
                    from_node=event_node,
                    to_node=node_id("tool", event["tool"]),
                    type=edge_type,
                    label="observed blocked" if edge_type == "event_blocked" else "observed allowed",
                    source=event.get("source_file", "unknown"),
                    confidence=event.get("confidence", "medium"),
                    evidence_layer="runtime",
                    blockers=[event.get("policy", "")] if edge_type == "event_blocked" and event.get("policy") else [],
                )
            )

    return graph, sorted(gaps.values(), key=lambda gap: gap.id)


def build_inventory(evidence: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    return {
        "agents": evidence.get("agents", {}).get("agents", []),
        "tools": all_tools(evidence),
        "identities": evidence.get("identity", {}).get("identities", []),
        "data_sources": evidence.get("data_catalog", {}).get("data_sources", []),
        "memory_stores": evidence.get("agents", {}).get("memory_stores", []),
        "policy_evaluations": evidence.get("approval_policy", {}).get("policy_evaluations", []),
    }
