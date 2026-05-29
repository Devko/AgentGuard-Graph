"""Read-only collector for Microsoft 365 Copilot agent packages."""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

from ..errors import EvidenceLoadError
from ..schemas import infer_target_system, load_json_file
from .mcp import infer_risk_tags

PROMPT_INPUT_SOURCE = {
    "id": "microsoft_365_copilot_user_prompt",
    "trust": "untrusted",
    "description": "User prompts sent to the Microsoft 365 Copilot agent.",
}
USER_DELEGATED_IDENTITY = {
    "id": "microsoft365:user-delegated",
    "type": "user_delegated",
    "target_system": "microsoft_365",
    "scopes": [],
    "permissions": [],
    "confidence": "low",
}

MICROSOFT_365_CAPABILITIES = {
    "Email",
    "GraphConnectors",
    "Meetings",
    "OneDriveAndSharePoint",
    "People",
    "TeamsMessages",
}

BUILTIN_CAPABILITY_TOOLS = {
    "CodeInterpreter": {
        "id": "copilot.CodeInterpreter.run_python",
        "name": "copilot.CodeInterpreter.run_python",
        "description": "Generate and execute Python code in the Microsoft 365 Copilot code interpreter sandbox.",
        "risk_tags": ["command_execution", "read_action", "write_action"],
        "target_system": "microsoft_365",
    },
    "Dataverse": {
        "id": "copilot.Dataverse.search",
        "name": "copilot.Dataverse.search",
        "description": "Search configured Microsoft Dataverse knowledge sources.",
        "risk_tags": ["read_action", "sensitive_read"],
        "target_system": "dataverse",
    },
    "Email": {
        "id": "copilot.Email.search",
        "name": "copilot.Email.search",
        "description": "Search email messages available to the user.",
        "risk_tags": ["read_action", "sensitive_read"],
        "target_system": "microsoft_365",
    },
    "EmbeddedKnowledge": {
        "id": "copilot.EmbeddedKnowledge.search",
        "name": "copilot.EmbeddedKnowledge.search",
        "description": "Search embedded files configured as agent knowledge.",
        "risk_tags": ["read_action", "sensitive_read"],
        "target_system": "microsoft_365",
    },
    "GraphConnectors": {
        "id": "copilot.GraphConnectors.search",
        "name": "copilot.GraphConnectors.search",
        "description": "Search configured Microsoft 365 Copilot connector sources.",
        "risk_tags": ["read_action", "sensitive_read"],
        "target_system": "microsoft_365",
    },
    "GraphicArt": {
        "id": "copilot.GraphicArt.generate",
        "name": "copilot.GraphicArt.generate",
        "description": "Generate images from user prompts.",
        "risk_tags": ["write_action"],
        "target_system": "microsoft_365",
    },
    "Meetings": {
        "id": "copilot.Meetings.search",
        "name": "copilot.Meetings.search",
        "description": "Search meeting content available to the user.",
        "risk_tags": ["read_action", "sensitive_read"],
        "target_system": "microsoft_365",
    },
    "OneDriveAndSharePoint": {
        "id": "copilot.OneDriveAndSharePoint.search",
        "name": "copilot.OneDriveAndSharePoint.search",
        "description": "Search configured OneDrive and SharePoint sources.",
        "risk_tags": ["read_action", "sensitive_read"],
        "target_system": "microsoft_365",
    },
    "People": {
        "id": "copilot.People.search",
        "name": "copilot.People.search",
        "description": "Search people data and related Microsoft 365 content available to the user.",
        "risk_tags": ["read_action", "sensitive_read"],
        "target_system": "microsoft_365",
    },
    "TeamsMessages": {
        "id": "copilot.TeamsMessages.search",
        "name": "copilot.TeamsMessages.search",
        "description": "Search configured Microsoft Teams message sources.",
        "risk_tags": ["read_action", "sensitive_read"],
        "target_system": "microsoft_365",
    },
    "WebSearch": {
        "id": "copilot.WebSearch.search",
        "name": "copilot.WebSearch.search",
        "description": "Search public web content for grounding information.",
        "risk_tags": ["network_access", "read_action"],
        "target_system": "web",
    },
}


class _Package:
    def __init__(self, source: Path, root: Path | None = None) -> None:
        self.source = source
        self.root = root or source

    def exists(self, relative: str) -> bool:
        raise NotImplementedError

    def read_json(self, relative: str) -> dict[str, Any]:
        raise NotImplementedError

    def list_json_files(self) -> list[str]:
        raise NotImplementedError

    def absolute_path(self, relative: str) -> Path | None:
        return None

    def display_name(self, relative: str) -> str:
        return str(relative).replace("\\", "/")


class _DirectoryPackage(_Package):
    def exists(self, relative: str) -> bool:
        return (self.root / _native_relative(relative)).exists()

    def read_json(self, relative: str) -> dict[str, Any]:
        return load_json_file(self.root / _native_relative(relative))

    def list_json_files(self) -> list[str]:
        files = []
        for path in sorted(self.root.rglob("*.json")):
            if any(part in {"node_modules", ".git", "__pycache__"} for part in path.parts):
                continue
            files.append(path.relative_to(self.root).as_posix())
        return files

    def absolute_path(self, relative: str) -> Path | None:
        path = self.root / _native_relative(relative)
        return path if path.exists() else None


class _ZipPackage(_Package):
    def __init__(self, source: Path) -> None:
        super().__init__(source)
        try:
            self.archive = zipfile.ZipFile(source)
        except zipfile.BadZipFile as exc:
            raise EvidenceLoadError(f"{source}: invalid Copilot app package zip") from exc
        self.names = {name.replace("\\", "/"): name for name in self.archive.namelist() if not name.endswith("/")}

    def exists(self, relative: str) -> bool:
        return _normalize_package_path(relative) in self.names

    def read_json(self, relative: str) -> dict[str, Any]:
        normalized = _normalize_package_path(relative)
        if normalized not in self.names:
            raise EvidenceLoadError(f"{self.source}:{relative}: file not found in Copilot app package")
        try:
            with self.archive.open(self.names[normalized]) as handle:
                data = json.loads(handle.read().decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise EvidenceLoadError(f"{self.source}:{relative}: invalid JSON: {exc.msg}") from exc
        if not isinstance(data, dict):
            raise EvidenceLoadError(f"{self.source}:{relative}: top-level JSON value must be an object")
        return data

    def list_json_files(self) -> list[str]:
        return sorted(name for name in self.names if name.lower().endswith(".json"))

    def display_name(self, relative: str) -> str:
        return f"{self.source.name}:{_normalize_package_path(relative)}"


def parse_copilot_agent(path: str | Path) -> dict[str, Any]:
    """Parse a Microsoft 365 Copilot declarative agent package or manifest.

    The adapter accepts an app package directory, app package zip, Microsoft 365
    app manifest, declarative agent manifest, or plugin manifest. It does not
    call Microsoft services; it only reads local JSON package artifacts.
    """
    source = Path(path)
    if not source.exists():
        raise EvidenceLoadError(f"{source}: Copilot agent package or manifest not found")
    package, start_file = _open_package(source)
    result = _empty_result(source)

    if start_file:
        data = package.read_json(start_file)
        _parse_manifest_like(package, start_file, data, result)
    else:
        manifest_file = _find_app_manifest(package)
        if manifest_file:
            _parse_app_manifest(package, manifest_file, package.read_json(manifest_file), result)
        else:
            declarative_file = _find_declarative_agent_manifest(package)
            if declarative_file:
                _parse_declarative_agent(package, declarative_file, package.read_json(declarative_file), result)
            else:
                result["warnings"].append(f"{source}: no Microsoft 365 Copilot app or declarative agent manifest found")

    if not result["agents"]:
        result["warnings"].append(
            f"{source}: no declarative agent inventory produced; provide a package with copilotAgents.declarativeAgents"
        )
    return result


def _open_package(source: Path) -> tuple[_Package, str]:
    if source.is_dir():
        return _DirectoryPackage(source), ""
    if source.suffix.lower() == ".zip":
        return _ZipPackage(source), ""
    return _DirectoryPackage(source.parent), source.name


def _empty_result(source: Path) -> dict[str, Any]:
    return {
        "source_file": str(source),
        "agents": [],
        "input_sources": [],
        "mcp_servers": [],
        "identities": [],
        "data_sources": [],
        "openapi_paths": [],
        "warnings": [],
    }


def _parse_manifest_like(
    package: _Package,
    relative: str,
    data: dict[str, Any],
    result: dict[str, Any],
) -> None:
    if _is_app_manifest(data):
        _parse_app_manifest(package, relative, data, result)
    elif _is_declarative_agent_manifest(data):
        _parse_declarative_agent(package, relative, data, result)
    elif _is_plugin_manifest(data):
        _append_plugin(package, relative, data, result, action_id=_stem(relative))
    else:
        result["warnings"].append(f"{package.display_name(relative)}: not a Microsoft 365 Copilot agent manifest")


def _is_app_manifest(data: dict[str, Any]) -> bool:
    return isinstance(data.get("copilotAgents"), dict) or "manifestVersion" in data


def _is_declarative_agent_manifest(data: dict[str, Any]) -> bool:
    return bool(data.get("instructions")) and (
        str(data.get("version", "")).startswith("v1.") or "capabilities" in data or "actions" in data
    )


def _is_plugin_manifest(data: dict[str, Any]) -> bool:
    return bool(data.get("schema_version")) and ("functions" in data or "runtimes" in data)


def _find_app_manifest(package: _Package) -> str:
    for candidate in ["manifest.json", "appPackage/manifest.json"]:
        if package.exists(candidate):
            try:
                if _is_app_manifest(package.read_json(candidate)):
                    return candidate
            except EvidenceLoadError:
                raise
    for relative in package.list_json_files():
        try:
            if _is_app_manifest(package.read_json(relative)):
                return relative
        except EvidenceLoadError:
            continue
    return ""


def _find_declarative_agent_manifest(package: _Package) -> str:
    for candidate in [
        "declarativeAgent.json",
        "declarative-agent.json",
        "copilot-agent.json",
        "appPackage/declarativeAgent.json",
        "appPackage/declarative-agent.json",
    ]:
        if package.exists(candidate):
            try:
                if _is_declarative_agent_manifest(package.read_json(candidate)):
                    return candidate
            except EvidenceLoadError:
                raise
    for relative in package.list_json_files():
        try:
            if _is_declarative_agent_manifest(package.read_json(relative)):
                return relative
        except EvidenceLoadError:
            continue
    return ""


def _parse_app_manifest(
    package: _Package,
    relative: str,
    data: dict[str, Any],
    result: dict[str, Any],
) -> None:
    refs = data.get("copilotAgents", {}).get("declarativeAgents", []) if isinstance(data.get("copilotAgents"), dict) else []
    if not isinstance(refs, list) or not refs:
        result["warnings"].append(f"{package.display_name(relative)}: no copilotAgents.declarativeAgents entries found")
        return
    if len(refs) > 1:
        result["warnings"].append(
            f"{package.display_name(relative)}: multiple declarative agents found; all local definitions were collected"
        )
    for ref in refs:
        if not isinstance(ref, dict) or not ref.get("file"):
            result["warnings"].append(f"{package.display_name(relative)}: declarative agent reference is missing file")
            continue
        agent_file = _join_relative(relative, str(ref["file"]))
        if not package.exists(agent_file):
            result["warnings"].append(f"{package.display_name(relative)}: referenced agent manifest not found: {ref['file']}")
            continue
        agent_data = package.read_json(agent_file)
        _parse_declarative_agent(package, agent_file, agent_data, result, app_manifest=data, agent_ref=ref)


def _parse_declarative_agent(
    package: _Package,
    relative: str,
    data: dict[str, Any],
    result: dict[str, Any],
    app_manifest: dict[str, Any] | None = None,
    agent_ref: dict[str, Any] | None = None,
) -> None:
    agent_ref = agent_ref or {}
    agent_id = str(data.get("id") or agent_ref.get("id") or _slug(data.get("name")) or _stem(relative))
    policy_id = f"{agent_id}-policy"
    tool_ids: list[str] = []
    identities = [USER_DELEGATED_IDENTITY]
    input_sources = [PROMPT_INPUT_SOURCE]
    servers: list[dict[str, Any]] = []
    data_sources: list[dict[str, Any]] = []

    builtin_tools = []
    for capability in data.get("capabilities", []):
        if not isinstance(capability, dict):
            continue
        capability_name = str(capability.get("name", ""))
        tool = _builtin_tool(capability_name, capability, relative)
        if tool:
            builtin_tools.append(tool)
            tool_ids.append(tool["id"])
        data_source = _capability_data_source(capability_name, capability, relative)
        if data_source:
            data_sources.append(data_source)
    if builtin_tools:
        servers.append(
            {
                "id": f"copilot:{agent_id}:builtins",
                "name": "Microsoft 365 Copilot built-in capabilities",
                "transport": "copilot_builtin",
                "auth": "user_delegated",
                "tools": builtin_tools,
                "source_file": package.display_name(relative),
            }
        )

    for action in data.get("actions", []):
        if not isinstance(action, dict):
            continue
        action_result = _parse_action(package, relative, action, result)
        tool_ids.extend(action_result.get("tool_ids", []))
        identities.extend(action_result.get("identities", []))
        servers.extend(action_result.get("mcp_servers", []))
        result["openapi_paths"].extend(action_result.get("openapi_paths", []))

    app_id = str((app_manifest or {}).get("id", ""))
    labels = {
        "platform": "microsoft_365_copilot",
        "copilot_schema_version": str(data.get("version", "")),
        "copilot_agent_manifest": package.display_name(relative),
    }
    if app_id:
        labels["microsoft_app_id"] = app_id
    result["agents"].append(
        {
            "id": agent_id,
            "name": _localized_string(data.get("name")) or agent_id,
            "runtime": "microsoft-365-copilot",
            "environment": "unknown",
            "autonomy": "unknown",
            "tools": sorted(set(tool_ids)),
            "input_sources": [item["id"] for item in input_sources],
            "identities": [identity["id"] for identity in _dedupe_identities(identities)],
            "approval_policy": policy_id,
            "labels": labels,
        }
    )
    result["input_sources"].extend(input_sources)
    result["identities"].extend(identities)
    result["mcp_servers"].extend(servers)
    result["data_sources"].extend(data_sources)


def _builtin_tool(capability_name: str, capability: dict[str, Any], relative: str) -> dict[str, Any] | None:
    base = BUILTIN_CAPABILITY_TOOLS.get(capability_name)
    if not base:
        if capability_name:
            risk_tags, risk_confidence = infer_risk_tags(capability_name, json.dumps(capability, sort_keys=True))
            return {
                "id": f"copilot.{capability_name}",
                "name": f"copilot.{capability_name}",
                "description": f"Microsoft 365 Copilot capability {capability_name}.",
                "risk_tags": risk_tags,
                "risk_confidence": risk_confidence,
                "risk_source": "inferred" if risk_tags else "unknown",
                "target_system": infer_target_system(capability_name),
                "source_file": relative,
                "raw": capability,
            }
        return None
    tool = dict(base)
    tool.update(
        {
            "risk_confidence": "high",
            "risk_source": "explicit",
            "source_file": relative,
            "raw": capability,
        }
    )
    return tool


def _capability_data_source(capability_name: str, capability: dict[str, Any], relative: str) -> dict[str, Any] | None:
    if capability_name == "Email":
        return _data_source("microsoft365.email", "Microsoft 365 email", "microsoft_365", ["employee_pii"], "high", relative, capability)
    if capability_name == "People":
        return _data_source("microsoft365.people", "Microsoft 365 people", "microsoft_365", ["employee_pii"], "high", relative, capability)
    if capability_name == "TeamsMessages":
        return _data_source("microsoft365.teams_messages", "Microsoft Teams messages", "microsoft_365", ["employee_pii"], "high", relative, capability)
    if capability_name == "Meetings":
        return _data_source("microsoft365.meetings", "Microsoft 365 meetings", "microsoft_365", ["employee_pii"], "high", relative, capability)
    if capability_name == "OneDriveAndSharePoint":
        return _data_source(
            "microsoft365.sharepoint_onedrive",
            "OneDrive and SharePoint knowledge",
            "microsoft_365",
            [],
            "unknown",
            relative,
            capability,
        )
    if capability_name == "GraphConnectors":
        connection_ids = [
            str(item.get("connection_id"))
            for item in capability.get("connections", [])
            if isinstance(item, dict) and item.get("connection_id")
        ]
        suffix = ",".join(connection_ids) if connection_ids else "all"
        return _data_source(
            f"microsoft365.graph_connectors:{suffix}",
            "Microsoft 365 Copilot connector knowledge",
            "microsoft_365",
            [],
            "unknown",
            relative,
            capability,
        )
    if capability_name == "Dataverse":
        tables = []
        for source in capability.get("knowledge_sources", []):
            if not isinstance(source, dict):
                continue
            for table in source.get("tables", []):
                if isinstance(table, dict) and table.get("table_name"):
                    tables.append(str(table["table_name"]))
        return _data_source(
            f"dataverse:{','.join(tables) if tables else 'configured'}",
            "Microsoft Dataverse knowledge",
            "dataverse",
            [],
            "unknown",
            relative,
            capability,
        )
    if capability_name == "EmbeddedKnowledge":
        return _data_source("microsoft365.embedded_knowledge", "Embedded agent knowledge files", "microsoft_365", [], "unknown", relative, capability)
    return None


def _data_source(
    data_id: str,
    name: str,
    target_system: str,
    data_classes: list[str],
    sensitivity: str,
    source_file: str,
    raw: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": data_id,
        "name": name,
        "target_system": target_system,
        "data_classes": data_classes,
        "sensitivity": sensitivity,
        "source_file": source_file,
        "raw": raw,
    }


def _parse_action(
    package: _Package,
    agent_manifest: str,
    action: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    if action.get("file"):
        plugin_file = _join_relative(agent_manifest, str(action["file"]))
        if not package.exists(plugin_file):
            result["warnings"].append(f"{package.display_name(agent_manifest)}: referenced plugin manifest not found: {action['file']}")
            return {}
        plugin_data = package.read_json(plugin_file)
        return _append_plugin(package, plugin_file, plugin_data, result, action_id=str(action.get("id") or _stem(plugin_file)))
    if _is_plugin_manifest(action):
        return _append_plugin(package, agent_manifest, action, result, action_id=str(action.get("name_for_model") or action.get("name_for_human") or "inline-plugin"))
    result["warnings"].append(f"{package.display_name(agent_manifest)}: action has neither file nor inline plugin manifest")
    return {}


def _append_plugin(
    package: _Package,
    relative: str,
    plugin: dict[str, Any],
    result: dict[str, Any],
    action_id: str,
) -> dict[str, Any]:
    plugin_name = str(
        plugin.get("name_for_model") or plugin.get("namespace") or plugin.get("name_for_human") or action_id or _stem(relative)
    )
    plugin_text = " ".join(
        [
            plugin_name,
            str(plugin.get("name_for_human", "")),
            str(plugin.get("description_for_human", "")),
            str(plugin.get("description_for_model", "")),
        ]
    )
    server_id = f"copilot-plugin:{_slug(plugin_name)}"
    runtime_target = _runtime_target(plugin.get("runtimes", []), plugin_text)
    identities = _plugin_identities(plugin_name, plugin.get("runtimes", []), runtime_target, package.display_name(relative))
    tools = _plugin_function_tools(plugin, server_id, runtime_target, package.display_name(relative))
    openapi_paths = _plugin_openapi_paths(package, relative, plugin.get("runtimes", []), result)
    mcp_servers = []

    if tools:
        mcp_servers.append(
            {
                "id": server_id,
                "name": str(plugin.get("name_for_human") or plugin_name),
                "transport": "copilot_plugin",
                "auth": _runtime_auth_label(plugin.get("runtimes", [])),
                "tools": tools,
                "source_file": package.display_name(relative),
            }
        )

    for runtime in plugin.get("runtimes", []):
        if not isinstance(runtime, dict) or runtime.get("type") != "RemoteMCPServer":
            continue
        mcp_server = _remote_mcp_server(package, relative, runtime, plugin_name, result)
        if mcp_server:
            mcp_servers.append(mcp_server)

    tool_ids = [tool["name"] for server in mcp_servers for tool in server.get("tools", []) if tool.get("name")]
    if not tool_ids and not openapi_paths:
        result["warnings"].append(
            f"{package.display_name(relative)}: plugin action has no functions, inline MCP tools, or local JSON OpenAPI spec"
        )
    return {
        "tool_ids": sorted(set(tool_ids)),
        "identities": identities,
        "mcp_servers": mcp_servers,
        "openapi_paths": openapi_paths,
    }


def _plugin_function_tools(
    plugin: dict[str, Any],
    server_id: str,
    target_system: str,
    source_file: str,
) -> list[dict[str, Any]]:
    tools = []
    for function in plugin.get("functions", []):
        if not isinstance(function, dict) or not function.get("name"):
            continue
        name = str(function["name"])
        description = _function_description(function)
        input_schema = function.get("parameters") if isinstance(function.get("parameters"), dict) else {}
        risk_tags, risk_confidence = infer_risk_tags(name, description, input_schema)
        security_tags = _security_info_risk_tags(function)
        if security_tags:
            risk_tags = sorted(set(risk_tags + security_tags))
            risk_confidence = "high"
        tools.append(
            {
                "id": name,
                "name": name,
                "description": description,
                "input_schema": input_schema,
                "risk_tags": risk_tags,
                "risk_confidence": risk_confidence,
                "risk_source": "explicit" if security_tags else ("inferred" if risk_tags else "unknown"),
                "target_system": target_system,
                "server_id": server_id,
                "source_file": source_file,
                "raw": function,
            }
        )
    return tools


def _function_description(function: dict[str, Any]) -> str:
    pieces = [str(function.get("description", ""))]
    states = function.get("states", {})
    if isinstance(states, dict):
        for state in states.values():
            if not isinstance(state, dict):
                continue
            pieces.append(str(state.get("description", "")))
            instructions = state.get("instructions", [])
            if isinstance(instructions, list):
                pieces.extend(str(item) for item in instructions if item)
    return " ".join(piece for piece in pieces if piece)


def _security_info_risk_tags(function: dict[str, Any]) -> list[str]:
    capabilities = function.get("capabilities", {})
    security_info = capabilities.get("security_info", {}) if isinstance(capabilities, dict) else {}
    data_handling = security_info.get("data_handling", []) if isinstance(security_info, dict) else []
    data = " ".join(str(item).lower() for item in data_handling if item)
    tags: set[str] = set()
    if "getprivatedata" in data or "private" in data:
        tags.add("sensitive_read")
    if "dataexport" in data or "export" in data:
        tags.update({"external_message", "data_exfiltration_sink"})
    if "resourcestateupdate" in data or "update" in data:
        tags.add("write_action")
    return sorted(tags)


def _remote_mcp_server(
    package: _Package,
    relative: str,
    runtime: dict[str, Any],
    plugin_name: str,
    result: dict[str, Any],
) -> dict[str, Any] | None:
    spec = runtime.get("spec", {}) if isinstance(runtime.get("spec"), dict) else {}
    description = spec.get("mcp_tool_description", {}) if isinstance(spec.get("mcp_tool_description"), dict) else {}
    tools = description.get("tools", [])
    if description.get("file"):
        tool_file = _join_relative(relative, str(description["file"]))
        if not package.exists(tool_file):
            result["warnings"].append(f"{package.display_name(relative)}: referenced MCP tool description not found: {description['file']}")
            return None
        data = package.read_json(tool_file)
        tools = data.get("tools", []) if isinstance(data.get("tools"), list) else []
    normalized_tools = []
    target_system = infer_target_system(f"{plugin_name} {spec.get('url', '')}")
    for tool in tools if isinstance(tools, list) else []:
        if not isinstance(tool, dict) or not tool.get("name"):
            continue
        name = str(tool["name"])
        description_text = str(tool.get("description", ""))
        input_schema = tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else tool.get("input_schema", {})
        if not isinstance(input_schema, dict):
            input_schema = {}
        risk_tags, risk_confidence = infer_risk_tags(name, description_text, input_schema)
        normalized_tools.append(
            {
                "id": name,
                "name": name,
                "description": description_text,
                "input_schema": input_schema,
                "risk_tags": risk_tags,
                "risk_confidence": risk_confidence,
                "risk_source": "inferred" if risk_tags else "unknown",
                "target_system": target_system,
                "source_file": package.display_name(relative),
                "raw": tool,
            }
        )
    return {
        "id": f"copilot-mcp:{_slug(plugin_name)}",
        "name": f"Copilot remote MCP plugin {plugin_name}",
        "transport": "remote_mcp",
        "auth": _auth_type(runtime.get("auth")),
        "tools": normalized_tools,
        "source_file": package.display_name(relative),
        "raw": runtime,
    }


def _plugin_openapi_paths(
    package: _Package,
    relative: str,
    runtimes: Any,
    result: dict[str, Any],
) -> list[str]:
    paths = []
    for runtime in runtimes if isinstance(runtimes, list) else []:
        if not isinstance(runtime, dict) or runtime.get("type") != "OpenApi":
            continue
        spec = runtime.get("spec", {}) if isinstance(runtime.get("spec"), dict) else {}
        spec_url = str(spec.get("url", ""))
        if not spec_url:
            continue
        if _is_absolute_url(spec_url):
            result["warnings"].append(
                f"{package.display_name(relative)}: remote OpenAPI spec {spec_url} was not fetched; provide local JSON OpenAPI evidence for operation-level analysis"
            )
            continue
        spec_file = _join_relative(relative, spec_url)
        if spec_file.lower().endswith((".yaml", ".yml")):
            result["warnings"].append(
                f"{package.display_name(relative)}: OpenAPI YAML spec {spec_url} is referenced; core scanner supports JSON OpenAPI evidence"
            )
            continue
        absolute = package.absolute_path(spec_file)
        if absolute:
            paths.append(str(absolute))
        elif package.exists(spec_file):
            result["warnings"].append(
                f"{package.display_name(relative)}: OpenAPI spec {spec_url} is inside a zip package; plugin function metadata was collected, but provide extracted JSON OpenAPI for operation-level analysis"
            )
        else:
            result["warnings"].append(f"{package.display_name(relative)}: referenced OpenAPI spec not found: {spec_url}")
    return paths


def _plugin_identities(plugin_name: str, runtimes: Any, target_system: str, source_file: str) -> list[dict[str, Any]]:
    identities = []
    for runtime in runtimes if isinstance(runtimes, list) else []:
        if not isinstance(runtime, dict):
            continue
        auth = runtime.get("auth", {})
        auth_type = _auth_type(auth)
        if auth_type == "none":
            continue
        identity_id = f"copilot:{_slug(plugin_name)}:{auth_type}"
        scopes = []
        if isinstance(auth, dict):
            scopes = [str(item) for item in auth.get("scopes", []) if item] if isinstance(auth.get("scopes"), list) else []
            if auth.get("reference_id"):
                scopes.append(f"reference_id:{auth['reference_id']}")
        identities.append(
            {
                "id": identity_id,
                "type": auth_type,
                "target_system": target_system,
                "scopes": sorted(set(scopes)),
                "permissions": [],
                "confidence": "low",
                "source_file": source_file,
            }
        )
    return identities


def _runtime_target(runtimes: Any, fallback_text: str) -> str:
    pieces = [fallback_text]
    for runtime in runtimes if isinstance(runtimes, list) else []:
        if not isinstance(runtime, dict):
            continue
        spec = runtime.get("spec", {}) if isinstance(runtime.get("spec"), dict) else {}
        pieces.extend(str(value) for value in [runtime.get("type"), spec.get("url"), spec.get("local_endpoint")] if value)
    return infer_target_system(" ".join(pieces))


def _runtime_auth_label(runtimes: Any) -> str:
    labels = sorted({_auth_type(runtime.get("auth")) for runtime in runtimes if isinstance(runtime, dict)})
    return ",".join(labels) if labels else "unknown"


def _auth_type(auth: Any) -> str:
    if isinstance(auth, dict):
        return str(auth.get("type", "unknown")).lower()
    if isinstance(auth, str):
        return auth.lower()
    return "unknown"


def _dedupe_identities(identities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    deduped = []
    for identity in identities:
        identity_id = identity.get("id")
        if not identity_id or identity_id in seen:
            continue
        seen.add(identity_id)
        deduped.append(identity)
    return deduped


def _localized_string(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ["short", "default", "en-us", "en"]:
            if value.get(key):
                return str(value[key])
    return ""


def _is_absolute_url(value: str) -> bool:
    parsed = urlparse(value)
    return bool(parsed.scheme and parsed.netloc)


def _join_relative(base_relative: str, relative: str) -> str:
    if relative.startswith("/"):
        return _normalize_package_path(relative.lstrip("/"))
    parent = PurePosixPath(_normalize_package_path(base_relative)).parent
    return _normalize_package_path(str(parent / relative))


def _native_relative(relative: str) -> Path:
    return Path(*PurePosixPath(_normalize_package_path(relative)).parts)


def _normalize_package_path(value: str) -> str:
    parts = []
    for part in PurePosixPath(str(value).replace("\\", "/")).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)


def _slug(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9_.-]+", "-", text)
    text = text.strip("-._")
    return text or "copilot-agent"


def _stem(relative: str) -> str:
    return PurePosixPath(_normalize_package_path(relative)).stem
