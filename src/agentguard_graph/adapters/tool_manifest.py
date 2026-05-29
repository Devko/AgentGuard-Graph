"""Read-only collector for code-adjacent agent tool manifests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..schemas import RISK_TAGS, infer_target_system, load_json_file, source_name, string_list


def parse_tool_manifest(path: str | Path) -> dict[str, Any]:
    """Parse a local JSON manifest that explicitly lists agent tools.

    This intentionally supports a small, framework-agnostic shape because many
    LangChain and custom-agent projects keep tool declarations close to code.
    """
    data = load_json_file(path)
    source = source_name(path)
    warnings = []
    raw_tools = _list_value(data, "tools", source, warnings)
    raw_agents = _list_value(data, "agents", source, warnings)
    raw_input_sources = _list_value(data, "input_sources", source, warnings)
    tools = []
    for index, tool in enumerate(raw_tools):
        if not isinstance(tool, (dict, str)):
            warnings.append(f"{source}: tools[{index}] must be an object or string")
            continue
        normalized = _normalize_tool(tool)
        if not normalized.get("name"):
            warnings.append(f"{source}: tools[{index}] is missing name")
        unknown_tags = _unknown_risk_tags(tool)
        if unknown_tags:
            warnings.append(f"{source}: tools[{index}] ignored unknown risk_tags: {', '.join(unknown_tags)}")
        tools.append(normalized)
    agents = []
    for index, agent in enumerate(raw_agents):
        if not isinstance(agent, dict):
            warnings.append(f"{source}: agents[{index}] must be an object")
            continue
        normalized = _normalize_agent(agent)
        if not normalized.get("id"):
            warnings.append(f"{source}: agents[{index}] is missing id/name")
        agents.append(normalized)
    input_sources = []
    for index, item in enumerate(raw_input_sources):
        if not isinstance(item, dict):
            warnings.append(f"{source}: input_sources[{index}] must be an object")
            continue
        normalized = _normalize_input_source(item)
        if not normalized.get("id"):
            warnings.append(f"{source}: input_sources[{index}] is missing id")
        input_sources.append(normalized)
    if not tools:
        warnings.append(f"{source}: tool manifest did not contain explicit tools")
    return {
        "schema_version": str(data.get("schema_version", "0.1")),
        "source_file": source,
        "tools": tools,
        "agents": agents,
        "input_sources": input_sources,
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


def _unknown_risk_tags(tool: dict[str, Any] | str) -> list[str]:
    if not isinstance(tool, dict):
        return []
    return sorted({tag for tag in string_list(tool.get("risk_tags")) if tag not in RISK_TAGS})


def _normalize_tool(tool: dict[str, Any] | str) -> dict[str, Any]:
    if isinstance(tool, str):
        return {"name": tool, "description": "", "target_system": infer_target_system(tool)}
    name = str(tool.get("name") or tool.get("id") or "")
    description = str(tool.get("description", ""))
    normalized: dict[str, Any] = {
        "name": name,
        "description": description,
        "target_system": str(tool.get("target_system") or infer_target_system(f"{name} {description}")),
    }
    input_schema = tool.get("input_schema") or tool.get("args_schema") or tool.get("schema")
    if isinstance(input_schema, dict):
        normalized["input_schema"] = input_schema
    explicit_tags = [tag for tag in string_list(tool.get("risk_tags")) if tag in RISK_TAGS]
    if explicit_tags:
        normalized["risk_tags"] = sorted(set(explicit_tags))
    return normalized


def _normalize_agent(agent: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(agent.get("id") or agent.get("name") or ""),
        "name": str(agent.get("name") or agent.get("id") or ""),
        "tools": string_list(agent.get("tools")),
        "input_sources": string_list(agent.get("input_sources")),
        "identities": string_list(agent.get("identities")),
        "autonomy": str(agent.get("autonomy", "unknown")),
        "environment": str(agent.get("environment", "unknown")),
    }


def _normalize_input_source(item: dict[str, Any]) -> dict[str, str]:
    return {
        "id": str(item.get("id", "")),
        "trust": str(item.get("trust", "unknown")),
        "description": str(item.get("description", "")),
    }
