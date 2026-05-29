"""Adapter for AgentGuard agent evidence files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..schemas import AUTONOMY_VALUES, ENVIRONMENT_VALUES, load_json_file, source_name, string_list


def parse_agents(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {
            "schema_version": "0.1",
            "agents": [],
            "tool_identity_bindings": [],
            "risk_acceptances": [],
            "input_sources": [],
            "memory_stores": [],
            "source_file": None,
            "warnings": [],
        }
    data = load_json_file(path)
    source = source_name(path)
    warnings = []
    agents = []
    for index, item in enumerate(_list_value(data, "agents", source, warnings)):
        if not isinstance(item, dict):
            warnings.append(f"{source}: agents[{index}] must be an object")
            continue
        agent_id = str(item.get("id", ""))
        if not agent_id:
            warnings.append(f"{source}: agents[{index}] is missing id")
        autonomy = item.get("autonomy", "unknown")
        environment = item.get("environment", "unknown")
        labels = item.get("labels", {})
        if labels is None:
            labels = {}
        elif not isinstance(labels, dict):
            warnings.append(f"{source}: agent {agent_id or index} labels must be an object")
            labels = {}
        if autonomy not in AUTONOMY_VALUES:
            warnings.append(f"{source}: agent {agent_id or index} autonomy normalized to unknown: {autonomy}")
        if environment not in ENVIRONMENT_VALUES:
            warnings.append(f"{source}: agent {agent_id or index} environment normalized to unknown: {environment}")
        agents.append(
            {
                "id": agent_id,
                "name": str(item.get("name") or item.get("id", "")),
                "owner": str(item.get("owner", "")),
                "runtime": str(item.get("runtime", "unknown")),
                "environment": environment if environment in ENVIRONMENT_VALUES else "unknown",
                "autonomy": autonomy if autonomy in AUTONOMY_VALUES else "unknown",
                "input_sources": string_list(item.get("input_sources")),
                "tools": string_list(item.get("tools")),
                "identities": string_list(item.get("identities")),
                "tool_identity_bindings": _tool_identity_bindings(
                    item.get("tool_identity_bindings"),
                    source,
                    f"agents[{index}].tool_identity_bindings",
                    warnings,
                    agent_id,
                ),
                "memory": string_list(item.get("memory")),
                "approval_policy": str(item.get("approval_policy", "")),
                "labels": labels,
                "source_file": source,
                "raw": item,
            }
        )
    top_level_bindings = _tool_identity_bindings(
        data.get("tool_identity_bindings"),
        source,
        "tool_identity_bindings",
        warnings,
        agents[0]["id"] if len(agents) == 1 else "",
    )
    for binding in top_level_bindings:
        for agent in agents:
            applies = binding.get("agent") == agent.get("id") or (
                not binding.get("agent")
                and binding.get("tool") in agent.get("tools", [])
                and binding.get("identity") in agent.get("identities", [])
            )
            if applies and binding not in agent["tool_identity_bindings"]:
                agent["tool_identity_bindings"].append(binding)
    risk_acceptances = _risk_acceptances(data.get("risk_acceptances"), source, warnings)
    input_sources = []
    for index, item in enumerate(_list_value(data, "input_sources", source, warnings)):
        if not isinstance(item, dict):
            warnings.append(f"{source}: input_sources[{index}] must be an object")
            continue
        input_source_id = str(item.get("id", ""))
        if not input_source_id:
            warnings.append(f"{source}: input_sources[{index}] is missing id")
        input_sources.append(
            {
                "id": input_source_id,
                "trust": str(item.get("trust", "unknown")),
                "description": str(item.get("description", "")),
                "source_file": source,
                "raw": item,
            }
        )
    memory_stores = []
    for index, item in enumerate(_list_value(data, "memory_stores", source, warnings)):
        if not isinstance(item, dict):
            warnings.append(f"{source}: memory_stores[{index}] must be an object")
            continue
        memory_id = str(item.get("id", ""))
        if not memory_id:
            warnings.append(f"{source}: memory_stores[{index}] is missing id")
        if item.get("data_classes") is not None and not isinstance(item.get("data_classes"), list):
            warnings.append(f"{source}: memory_store {memory_id or index} data_classes should be a list")
        if item.get("source_evidence") is not None and not isinstance(item.get("source_evidence"), list):
            warnings.append(f"{source}: memory_store {memory_id or index} source_evidence should be a list")
        memory_stores.append(
            {
                "id": memory_id,
                "persistence": str(item.get("persistence", "unknown")),
                "retention_policy": str(item.get("retention_policy", "unknown")),
                "owner": str(item.get("owner") or item.get("data_owner") or item.get("steward") or ""),
                "retention_period": str(item.get("retention_period") or item.get("retention_days") or ""),
                "deletion_policy": str(item.get("deletion_policy") or item.get("deletion_workflow") or item.get("deletion_sla") or ""),
                "data_classes": string_list(item.get("data_classes")),
                "source_evidence": string_list(item.get("source_evidence")),
                "source_file": source,
                "raw": item,
            }
        )
    return {
        "schema_version": str(data.get("schema_version", "0.1")),
        "agents": agents,
        "tool_identity_bindings": top_level_bindings,
        "risk_acceptances": risk_acceptances,
        "input_sources": input_sources,
        "memory_stores": memory_stores,
        "source_file": source,
        "warnings": warnings,
    }


def _list_value(data: dict[str, Any], key: str, source: str, warnings: list[str]) -> list[Any]:
    value = data.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list):
        warnings.append(f"{source}: {key} must be a list")
        return []
    return value


def _tool_identity_bindings(
    value: Any,
    source: str,
    label: str,
    warnings: list[str],
    default_agent: str = "",
) -> list[dict[str, str]]:
    if value is None:
        return []
    if isinstance(value, dict):
        value = [{"tool": tool, "identity": identity} for tool, identity in value.items()]
    if not isinstance(value, list):
        warnings.append(f"{source}: {label} must be a list or object")
        return []
    bindings: list[dict[str, str]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            warnings.append(f"{source}: {label}[{index}] must be an object")
            continue
        tool = str(item.get("tool") or item.get("tool_id") or item.get("name") or "")
        identity = str(item.get("identity") or item.get("identity_id") or "")
        agent = str(item.get("agent") or item.get("agent_id") or default_agent)
        if not tool:
            warnings.append(f"{source}: {label}[{index}] is missing tool")
        if not identity:
            warnings.append(f"{source}: {label}[{index}] is missing identity")
        if not tool or not identity:
            continue
        bindings.append({"agent": agent, "tool": tool, "identity": identity})
    return bindings


def _risk_acceptances(value: Any, source: str, warnings: list[str]) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        warnings.append(f"{source}: risk_acceptances must be a list")
        return []
    acceptances: list[dict[str, Any]] = []
    scope_keys = ["finding_id", "path_id", "rule_id", "agent", "owner", "environment", "business_unit"]
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            warnings.append(f"{source}: risk_acceptances[{index}] must be an object")
            continue
        raw_scope = item.get("scope", {})
        if raw_scope is None:
            raw_scope = {}
        if not isinstance(raw_scope, dict):
            warnings.append(f"{source}: risk_acceptances[{index}].scope must be an object")
            raw_scope = {}
        scope = {}
        for key in scope_keys:
            scoped_value = raw_scope.get(key, item.get(key))
            if scoped_value is not None and scoped_value != "":
                scope[key] = str(scoped_value)
        acceptances.append(
            {
                "id": str(item.get("id", "")),
                "status": str(item.get("status", "accepted") or "accepted"),
                "owner": str(item.get("owner") or item.get("accepted_by") or ""),
                "reason": str(item.get("reason", "")),
                "ticket": str(item.get("ticket") or item.get("reference") or ""),
                "accepted_at": str(item.get("accepted_at", "")),
                "expires_at": str(item.get("expires_at") or item.get("accepted_until") or item.get("expires_on") or ""),
                "scope": scope,
                "source_file": source,
                "raw": item,
            }
        )
    return acceptances
