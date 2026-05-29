"""Read-only collector for common local MCP client configuration files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..schemas import RISK_TAGS, infer_target_system, load_json_file, source_name, string_list


def parse_mcp_client_config(path: str | Path) -> dict[str, Any]:
    """Convert common MCP client config shapes into AgentGuard MCP evidence.

    This parser only reads local JSON. It never starts MCP server commands and
    cannot list tools from a server that only appears as a command entry.
    """
    data = load_json_file(path)
    source = source_name(path)
    server_items = _server_items(data)
    servers: list[dict[str, Any]] = []
    warnings: list[str] = _container_warnings(data, source)
    for fallback_id, config in server_items:
        if not isinstance(config, dict):
            continue
        server_id = str(config.get("id") or config.get("name") or fallback_id)
        if not server_id:
            continue
        raw_tools = config.get("tools", [])
        if raw_tools is None:
            raw_tools = []
        if not isinstance(raw_tools, list):
            warnings.append(f"{source}: MCP server {server_id} tools must be a list")
            raw_tools = []
        tools = [_normalize_tool(tool, server_id) for tool in raw_tools if isinstance(tool, (dict, str))]
        skipped_tools = len([tool for tool in raw_tools if not isinstance(tool, (dict, str))])
        if skipped_tools:
            warnings.append(f"{source}: MCP server {server_id} skipped {skipped_tools} malformed tool entries")
        servers.append(
            {
                "id": server_id,
                "name": str(config.get("name") or server_id),
                "transport": _transport(config),
                "auth": str(config.get("auth", "unknown")),
                "tools": tools,
            }
        )
        if not tools:
            warnings.append(
                f"{source}: MCP server {server_id} has config evidence but no tool descriptors; "
                "provide an MCP descriptor export or add tools manually."
            )
    return {
        "schema_version": "0.1",
        "servers": servers,
        "source_file": source,
        "warnings": warnings,
    }


def _container_warnings(data: dict[str, Any], source: str) -> list[str]:
    warnings = []
    for key in ["mcpServers", "mcp_servers", "servers"]:
        if key in data and not isinstance(data[key], (dict, list)):
            warnings.append(f"{source}: {key} must be an object or list")
    mcp = data.get("mcp")
    if isinstance(mcp, dict):
        for key in ["mcpServers", "mcp_servers", "servers"]:
            if key in mcp and not isinstance(mcp[key], (dict, list)):
                warnings.append(f"{source}: mcp.{key} must be an object or list")
    elif "mcp" in data and mcp is not None:
        warnings.append(f"{source}: mcp must be an object")
    return warnings


def _server_items(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    containers: list[Any] = []
    for key in ["mcpServers", "mcp_servers", "servers"]:
        if key in data:
            containers.append(data[key])
    mcp = data.get("mcp")
    if isinstance(mcp, dict):
        for key in ["mcpServers", "mcp_servers", "servers"]:
            if key in mcp:
                containers.append(mcp[key])

    items: list[tuple[str, dict[str, Any]]] = []
    for container in containers:
        if isinstance(container, dict):
            items.extend((str(name), value) for name, value in container.items() if isinstance(value, dict))
        elif isinstance(container, list):
            for index, value in enumerate(container):
                if isinstance(value, dict):
                    items.append((str(value.get("id") or value.get("name") or f"server-{index + 1}"), value))
    return items


def _transport(config: dict[str, Any]) -> str:
    if config.get("transport"):
        return str(config["transport"])
    if config.get("command"):
        return "stdio"
    url = str(config.get("url") or "")
    if url.startswith("http"):
        return "http"
    return "unknown"


def _normalize_tool(tool: dict[str, Any] | str, server_id: str) -> dict[str, Any]:
    if isinstance(tool, str):
        return {
            "name": tool,
            "description": "",
            "target_system": infer_target_system(f"{server_id} {tool}"),
        }
    name = str(tool.get("name") or tool.get("id") or "")
    normalized = {
        "name": name,
        "description": str(tool.get("description", "")),
        "target_system": str(tool.get("target_system") or infer_target_system(f"{server_id} {name} {tool.get('description', '')}")),
    }
    input_schema = tool.get("input_schema")
    if isinstance(input_schema, dict):
        normalized["input_schema"] = input_schema
    explicit_tags = [tag for tag in string_list(tool.get("risk_tags")) if tag in RISK_TAGS]
    if explicit_tags:
        normalized["risk_tags"] = sorted(set(explicit_tags))
    return normalized
