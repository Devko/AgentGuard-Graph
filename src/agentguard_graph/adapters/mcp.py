"""Adapter for static MCP server evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..schemas import RISK_TAGS, infer_target_system, load_json_file, source_name, string_list


def infer_risk_tags(name: str, description: str = "", input_schema: dict[str, Any] | None = None) -> tuple[list[str], str]:
    """Infer weak tool risk tags from descriptive evidence only."""
    schema_text = json.dumps(input_schema or {}, sort_keys=True).lower()
    text = f"{name} {description} {schema_text}".lower()
    tags: set[str] = set()
    strong = False

    if any(word in text for word in ["send", "email", "message", "slack", "webhook", "external recipient"]):
        tags.update({"external_message", "data_exfiltration_sink"})
        strong = True
    if any(word in text for word in ["refund", "payment", "invoice", "charge", "payout"]):
        tags.add("financial_action")
        strong = True
    if any(word in text for word in ["deploy", "terraform", "kubernetes", "production", "apply"]):
        tags.add("production_write")
        strong = True
    if any(word in text for word in ["shell", "command", "execute", "exec", "run command", "terminal"]):
        tags.add("command_execution")
        strong = True
    if any(word in text for word in ["secret", "token", "credential", "private key", ".env"]):
        tags.add("secret_access")
        strong = True
    if any(word in text for word in ["delete", "destroy", "remove", "drop"]):
        tags.add("destructive_action")
    if any(word in text for word in ["write", "create", "update", "patch", "commit", "pull request"]):
        tags.add("write_action")
    if any(word in text for word in ["repo", "repository", "github"]):
        if "write_action" in tags:
            tags.add("repository_write")
        else:
            tags.add("filesystem_read")
    if any(word in text for word in ["file", "filesystem", "path"]):
        tags.add("filesystem_write" if "write_action" in tags else "filesystem_read")
    if any(word in text for word in ["get", "read", "list", "search", "contact", "customer", "case", "account", "profile"]):
        tags.add("sensitive_read")
    if not tags and any(word in text for word in ["read", "get", "list"]):
        tags.add("read_action")

    confidence = "medium" if strong else "low"
    return sorted(tags), confidence


def parse_mcp(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {"schema_version": "0.1", "servers": [], "tools": [], "source_file": None, "warnings": []}
    data = load_json_file(path)
    source = source_name(path)
    servers = []
    tools = []
    warnings = []
    raw_servers = data.get("servers", [])
    if raw_servers is None:
        raw_servers = []
    if not isinstance(raw_servers, list):
        warnings.append(f"{source}: servers must be a list")
        raw_servers = []
    for server_index, server in enumerate(raw_servers):
        if not isinstance(server, dict):
            warnings.append(f"{source}: servers[{server_index}] must be an object")
            continue
        server_id = str(server.get("id", ""))
        if not server_id:
            warnings.append(f"{source}: servers[{server_index}] is missing id")
        server_tools: list[dict[str, Any]] = []
        servers.append(
            {
                "id": server_id,
                "name": str(server.get("name") or server_id),
                "transport": str(server.get("transport", "unknown")),
                "auth": str(server.get("auth", "unknown")),
                "tools": server_tools,
                "source_file": source,
                "raw": server,
            }
        )
        raw_tools = server.get("tools", [])
        if raw_tools is None:
            raw_tools = []
        if not isinstance(raw_tools, list):
            warnings.append(f"{source}: server {server_id or server_index} tools must be a list")
            raw_tools = []
        for tool_index, tool in enumerate(raw_tools):
            if isinstance(tool, str):
                tool = {"name": tool}
            if not isinstance(tool, dict):
                warnings.append(f"{source}: server {server_id or server_index} tools[{tool_index}] must be an object or string")
                continue
            name = str(tool.get("name", ""))
            if not name:
                warnings.append(f"{source}: server {server_id or server_index} tools[{tool_index}] is missing name")
            explicit_tags = [tag for tag in string_list(tool.get("risk_tags")) if tag in RISK_TAGS]
            if explicit_tags:
                risk_tags = sorted(set(explicit_tags))
                risk_confidence = "high"
                risk_source = "explicit"
            else:
                risk_tags, risk_confidence = infer_risk_tags(
                    name, str(tool.get("description", "")), tool.get("input_schema")
                )
                risk_source = "inferred" if risk_tags else "unknown"
            target = str(tool.get("target_system") or infer_target_system(f"{name} {tool.get('description', '')}"))
            server_tools.append(
                {
                    "name": name,
                    "description": str(tool.get("description", "")),
                    "target_system": target,
                }
            )
            tools.append(
                {
                    "id": name,
                    "name": name,
                    "description": str(tool.get("description", "")),
                    "input_schema": tool.get("input_schema", {}) if isinstance(tool.get("input_schema", {}), dict) else {},
                    "risk_tags": risk_tags,
                    "risk_confidence": risk_confidence,
                    "risk_source": risk_source,
                    "target_system": target,
                    "server_id": server_id,
                    "source_file": source,
                    "raw": tool,
                }
            )
    return {
        "schema_version": str(data.get("schema_version", "0.1")),
        "servers": servers,
        "tools": tools,
        "source_file": source,
        "warnings": warnings,
    }
