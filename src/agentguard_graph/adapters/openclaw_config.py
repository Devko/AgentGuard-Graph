"""Read-only collector for OpenClaw JSON configuration exports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..errors import EvidenceLoadError
from ..schemas import load_json_file, source_name, string_list

OPENCLAW_TOOL_GROUPS = {
    "exec": {
        "name": "openclaw.exec",
        "description": "OpenClaw execution tool group",
        "risk_tags": ["command_execution"],
        "target_system": "local_workspace",
    },
    "shell": {
        "name": "openclaw.shell",
        "description": "OpenClaw shell tool group",
        "risk_tags": ["command_execution"],
        "target_system": "local_workspace",
    },
    "fs": {
        "name": "openclaw.fs",
        "description": "OpenClaw filesystem tool group",
        "risk_tags": ["filesystem_read", "filesystem_write"],
        "target_system": "local_workspace",
    },
    "filesystem": {
        "name": "openclaw.filesystem",
        "description": "OpenClaw filesystem tool group",
        "risk_tags": ["filesystem_read", "filesystem_write"],
        "target_system": "local_workspace",
    },
    "browser": {
        "name": "openclaw.browser",
        "description": "OpenClaw browser tool group",
        "risk_tags": ["network_access"],
        "target_system": "web",
    },
    "github": {
        "name": "openclaw.github",
        "description": "OpenClaw GitHub tool group",
        "risk_tags": ["repository_write", "code_write"],
        "target_system": "github",
    },
}


def parse_openclaw_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    if config_path.suffix.lower() in {".yaml", ".yml"}:
        raise EvidenceLoadError(f"{config_path}: OpenClaw YAML config is not supported yet; export or convert to JSON")
    data = load_json_file(config_path)
    source = source_name(path)
    defaults = data.get("agents", {}).get("defaults", {}) if isinstance(data.get("agents"), dict) else {}
    warnings = []
    agent_items = _agent_items(data, source, warnings)
    tools_by_name: dict[str, dict[str, Any]] = {}

    global_tools = _tool_names_and_descriptors(data.get("tools", {}), tools_by_name, warnings, source, "tools")
    default_tools = sorted(
        set(global_tools + _tool_names_and_descriptors(defaults.get("tools", {}), tools_by_name, warnings, source, "agents.defaults.tools"))
    )
    agents = []
    for index, agent in enumerate(agent_items):
        agent_tools = sorted(
            set(default_tools + _tool_names_and_descriptors(agent.get("tools", {}), tools_by_name, warnings, source, f"agents[{index}].tools"))
        )
        agent_id = str(agent.get("id") or agent.get("name") or f"openclaw-agent-{index + 1}")
        agents.append(
            {
                "id": agent_id,
                "name": str(agent.get("name") or agent_id),
                "runtime": str(agent.get("runtime") or data.get("runtime") or "openclaw"),
                "tools": agent_tools,
                "input_sources": _input_sources_for_agent(agent, data),
                "autonomy": "unknown",
                "environment": str(agent.get("environment") or data.get("environment") or "unknown"),
            }
        )

    if not agents:
        warnings.append(f"{source}: no OpenClaw agents found under agents.list")
    if not tools_by_name:
        warnings.append(f"{source}: no explicit OpenClaw tool groups or allowlisted tools found")
    input_sources = _input_source_records(data)
    return {
        "schema_version": "0.1",
        "source_file": source,
        "agents": agents,
        "tools": sorted(tools_by_name.values(), key=lambda item: item["name"]),
        "input_sources": input_sources,
        "warnings": warnings,
    }


def _agent_items(data: dict[str, Any], source: str, warnings: list[str]) -> list[dict[str, Any]]:
    agents = data.get("agents", {})
    if isinstance(agents, dict):
        agent_list = agents.get("list", [])
        if isinstance(agent_list, list):
            result = []
            for index, agent in enumerate(agent_list):
                if isinstance(agent, dict):
                    result.append(agent)
                else:
                    warnings.append(f"{source}: agents.list[{index}] must be an object")
            return result
        if agent_list not in (None, []):
            warnings.append(f"{source}: agents.list must be a list")
    if isinstance(agents, list):
        result = []
        for index, agent in enumerate(agents):
            if isinstance(agent, dict):
                result.append(agent)
            else:
                warnings.append(f"{source}: agents[{index}] must be an object")
        return result
    if "agents" in data and agents not in ({}, None):
        warnings.append(f"{source}: agents must be an object or list")
    return []


def _tool_names_and_descriptors(
    config: Any,
    tools_by_name: dict[str, dict[str, Any]],
    warnings: list[str],
    source: str,
    context: str,
) -> list[str]:
    names: list[str] = []
    if isinstance(config, list):
        for index, item in enumerate(config):
            if isinstance(item, str):
                names.append(item)
                tools_by_name.setdefault(item, {"name": item, "description": "", "target_system": "unknown"})
            elif isinstance(item, dict):
                names.extend(_tool_names_and_descriptors(item, tools_by_name, warnings, source, f"{context}[{index}]"))
            else:
                warnings.append(f"{source}: {context}[{index}] must be an object or string")
        return names
    if not isinstance(config, dict):
        if config not in ({}, [], None):
            warnings.append(f"{source}: {context} must be an object or list")
        return names

    for key in ["allow", "include", "enabled"]:
        value = config.get(key)
        if isinstance(value, dict):
            warnings.append(f"{source}: {context}.{key} must be a string or list")
            continue
        for tool_name in string_list(value):
            names.append(tool_name)
            tools_by_name.setdefault(tool_name, {"name": tool_name, "description": "", "target_system": "unknown"})

    for group_name, descriptor in OPENCLAW_TOOL_GROUPS.items():
        group_config = config.get(group_name)
        if group_config in (None, False):
            continue
        if isinstance(group_config, dict) and group_config.get("enabled") is False:
            continue
        descriptor_copy = dict(descriptor)
        names.append(descriptor_copy["name"])
        tools_by_name.setdefault(descriptor_copy["name"], descriptor_copy)
    return names


def _input_sources_for_agent(agent: dict[str, Any], data: dict[str, Any]) -> list[str]:
    explicit = string_list(agent.get("input_sources"))
    channel_inputs = _channel_input_ids(data)
    return sorted(set(explicit + channel_inputs))


def _input_source_records(data: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"id": channel_id, "trust": "untrusted", "description": f"OpenClaw channel: {channel_id}"}
        for channel_id in _channel_input_ids(data)
    ]


def _channel_input_ids(data: dict[str, Any]) -> list[str]:
    channels = data.get("channels", {})
    if not isinstance(channels, dict):
        return []
    return sorted(str(name) for name, value in channels.items() if isinstance(value, dict) and value.get("enabled", True) is not False)
