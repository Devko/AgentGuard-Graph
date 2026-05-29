"""Static collector for common code-first agent frameworks."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..schemas import infer_target_system, source_name
from .mcp import infer_risk_tags


@dataclass(frozen=True)
class FrameworkSpec:
    id: str
    name: str
    modules: tuple[str, ...]
    agent_calls: tuple[str, ...]
    dependency_hints: tuple[str, ...] = ()
    tool_keywords: tuple[str, ...] = ("tools", "tool", "functions", "function_tools", "toolsets", "mcp_servers")


TOP_AGENT_FRAMEWORKS: tuple[FrameworkSpec, ...] = (
    FrameworkSpec(
        id="langchain_langgraph",
        name="LangChain / LangGraph",
        modules=("langchain", "langgraph"),
        agent_calls=("AgentExecutor", "create_agent", "create_react_agent", "create_tool_calling_agent", "StateGraph"),
        dependency_hints=("langchain", "langchain-core", "langchain-community", "langgraph"),
    ),
    FrameworkSpec(
        id="autogen",
        name="Microsoft AutoGen",
        modules=("autogen", "autogen_agentchat"),
        agent_calls=("AssistantAgent", "ConversableAgent", "UserProxyAgent", "GroupChat", "RoutedAgent"),
        dependency_hints=("autogen", "autogen-agentchat", "pyautogen"),
    ),
    FrameworkSpec(
        id="llamaindex",
        name="LlamaIndex agents/workflows",
        modules=("llama_index", "llama_agents"),
        agent_calls=("FunctionAgent", "ReActAgent", "AgentWorkflow", "Workflow"),
        dependency_hints=("llama-index", "llama-agents"),
    ),
    FrameworkSpec(id="crewai", name="CrewAI", modules=("crewai",), agent_calls=("Agent", "Crew", "CrewBase"), dependency_hints=("crewai",)),
    FrameworkSpec(id="agno", name="Agno", modules=("agno",), agent_calls=("Agent", "Team", "AgentOS"), dependency_hints=("agno",)),
    FrameworkSpec(
        id="semantic_kernel",
        name="Microsoft Semantic Kernel",
        modules=("semantic_kernel",),
        agent_calls=("Agent", "ChatCompletionAgent", "AzureAIAgent", "OpenAIAssistantAgent"),
        dependency_hints=("semantic-kernel",),
    ),
    FrameworkSpec(
        id="microsoft_agent_framework",
        name="Microsoft Agent Framework",
        modules=("agent_framework",),
        agent_calls=("Agent", "ChatAgent", "Workflow"),
        dependency_hints=("agent-framework",),
    ),
    FrameworkSpec(
        id="openai_agents",
        name="OpenAI Agents SDK",
        modules=("agents",),
        agent_calls=("Agent", "SandboxAgent"),
        dependency_hints=("openai-agents",),
    ),
    FrameworkSpec(
        id="google_adk",
        name="Google Agent Development Kit",
        modules=("google.adk",),
        agent_calls=("Agent", "LlmAgent", "SequentialAgent", "ParallelAgent", "LoopAgent"),
        dependency_hints=("google-adk",),
    ),
    FrameworkSpec(id="haystack", name="Haystack", modules=("haystack",), agent_calls=("Agent", "Pipeline"), dependency_hints=("haystack-ai",)),
    FrameworkSpec(id="pydantic_ai", name="Pydantic AI", modules=("pydantic_ai",), agent_calls=("Agent",), dependency_hints=("pydantic-ai",)),
    FrameworkSpec(
        id="camel",
        name="CAMEL",
        modules=("camel",),
        agent_calls=("ChatAgent", "RolePlaying", "TaskSpecifyAgent"),
        dependency_hints=("camel-ai",),
    ),
)

SKIP_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "site-packages",
    "venv",
}
MAX_PYTHON_FILES = 250
DEFAULT_INPUT_SOURCE = {
    "id": "agent_user_prompt",
    "trust": "untrusted",
    "description": "User-controlled prompts or task requests sent to the agent runtime.",
}


def parse_framework_code(path: str | Path) -> dict[str, Any]:
    """Parse local source/config evidence for popular code-first frameworks.

    This is intentionally static. It does not import project code, execute
    decorators, call framework CLIs, or resolve dynamic tool factories.
    """
    root = Path(path)
    if not root.exists():
        return _result(root, warnings=[f"{root}: framework source path not found"])
    files = _python_files(root)
    warnings = []
    if len(files) >= MAX_PYTHON_FILES:
        warnings.append(f"{root}: scanned first {MAX_PYTHON_FILES} Python files; pass a narrower --framework-code path for deeper coverage")

    agents: list[dict[str, Any]] = []
    tools_by_name: dict[str, dict[str, Any]] = {}
    frameworks_seen: dict[str, dict[str, Any]] = {}
    input_sources = [dict(DEFAULT_INPUT_SOURCE)]

    for file_path in files[:MAX_PYTHON_FILES]:
        parsed = _parse_python_file(file_path)
        warnings.extend(parsed.get("warnings", []))
        for framework in parsed.get("frameworks", []):
            frameworks_seen.setdefault(framework["id"], framework)
        for tool in parsed.get("tools", []):
            tools_by_name.setdefault(tool["name"], tool)
        for agent in parsed.get("agents", []):
            agents.append(agent)

    crew_config = _parse_crewai_config(root)
    if crew_config["agents"]:
        frameworks_seen.setdefault("crewai", {"id": "crewai", "name": "CrewAI"})
        agents.extend(crew_config["agents"])
        for tool in crew_config["tools"]:
            tools_by_name.setdefault(tool["name"], tool)
    warnings.extend(crew_config["warnings"])

    agents = _dedupe_agents(agents)
    if not frameworks_seen and not agents and not tools_by_name:
        warnings.append(f"{root}: no supported agent framework imports or CrewAI agent config were extracted")
    if not agents and frameworks_seen:
        agents = [
            {
                "id": f"{framework_id}-agent",
                "name": framework["name"],
                "runtime": framework_id,
                "environment": "unknown",
                "autonomy": "unknown",
                "tools": [],
                "input_sources": [DEFAULT_INPUT_SOURCE["id"]],
                "identities": [],
                "labels": {"framework": framework_id, "collector": "framework_code_static"},
            }
            for framework_id, framework in sorted(frameworks_seen.items())
        ]

    for agent in agents:
        for tool_name in agent.get("tools", []):
            tools_by_name.setdefault(tool_name, _tool(tool_name, "", str(root), "framework-code"))
    if frameworks_seen and not tools_by_name:
        warnings.append(f"{root}: framework imports found, but no static tool declarations were extracted")
    if agents:
        warnings.append(
            f"{root}: static framework collector does not execute code; provide identity, permission, approval, and runtime exports for confidence"
        )
    return _result(
        root,
        frameworks=sorted(frameworks_seen.values(), key=lambda item: item["id"]),
        agents=agents,
        tools=sorted(tools_by_name.values(), key=lambda item: item["name"]),
        input_sources=input_sources if agents else [],
        warnings=warnings,
    )


def _result(
    source: Path,
    *,
    frameworks: list[dict[str, Any]] | None = None,
    agents: list[dict[str, Any]] | None = None,
    tools: list[dict[str, Any]] | None = None,
    input_sources: list[dict[str, str]] | None = None,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "source_file": str(source),
        "frameworks": frameworks or [],
        "agents": agents or [],
        "tools": tools or [],
        "input_sources": input_sources or [],
        "warnings": warnings or [],
    }


def _python_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if root.suffix == ".py" else []
    files = []
    for path in sorted(root.rglob("*.py")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        files.append(path)
        if len(files) >= MAX_PYTHON_FILES:
            break
    return files


def _parse_python_file(path: Path) -> dict[str, Any]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeDecodeError) as exc:
        return {"agents": [], "tools": [], "frameworks": [], "warnings": [f"{path}: skipped Python parse: {exc}"]}

    aliases = _import_aliases(tree)
    frameworks_seen = _frameworks_from_imports(aliases)
    agents = []
    tools_by_name: dict[str, dict[str, Any]] = {}
    assignments: dict[ast.AST, str] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            assignments[child] = _assignment_name(parent)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        qualified = _qualified_call_name(node.func, aliases)
        short = qualified.rsplit(".", 1)[-1]
        matched = _match_framework(qualified, short)
        if not matched:
            continue
        framework, spec = matched
        frameworks_seen.setdefault(spec.id, {"id": spec.id, "name": spec.name})
        if short not in spec.agent_calls:
            continue
        agent_id = _agent_id(node, assignments.get(node) or short)
        tool_names = _extract_tool_names(node, spec.tool_keywords)
        for tool_name in tool_names:
            tools_by_name.setdefault(tool_name, _tool(tool_name, f"{spec.name} tool reference", str(path), f"framework-code:{spec.id}"))
        agents.append(
            {
                "id": agent_id,
                "name": _keyword_string(node, ["name", "role"]) or agent_id,
                "runtime": framework,
                "environment": "unknown",
                "autonomy": "unknown",
                "tools": sorted(set(tool_names)),
                "input_sources": [DEFAULT_INPUT_SOURCE["id"]],
                "identities": [],
                "labels": {
                    "framework": framework,
                    "framework_name": spec.name,
                    "collector": "framework_code_static",
                    "source_file": source_name(path),
                },
            }
        )

    return {
        "agents": agents,
        "tools": sorted(tools_by_name.values(), key=lambda item: item["name"]),
        "frameworks": sorted(frameworks_seen.values(), key=lambda item: item["id"]),
        "warnings": [],
    }


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _frameworks_from_imports(aliases: dict[str, str]) -> dict[str, dict[str, Any]]:
    frameworks = {}
    for module in aliases.values():
        for spec in TOP_AGENT_FRAMEWORKS:
            if _module_matches(module, spec.modules):
                frameworks.setdefault(spec.id, {"id": spec.id, "name": spec.name})
    return frameworks


def _match_framework(qualified: str, short: str) -> tuple[str, FrameworkSpec] | None:
    for spec in TOP_AGENT_FRAMEWORKS:
        if _module_matches(qualified, spec.modules) and short in spec.agent_calls:
            return spec.id, spec
    return None


def _module_matches(module: str, prefixes: tuple[str, ...]) -> bool:
    return any(module == prefix or module.startswith(f"{prefix}.") for prefix in prefixes)


def _qualified_call_name(func: ast.AST, aliases: dict[str, str]) -> str:
    dotted = _dotted_name(func)
    if not dotted:
        return ""
    head, _, tail = dotted.partition(".")
    if head in aliases:
        return aliases[head] + (f".{tail}" if tail else "")
    return dotted


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _assignment_name(parent: ast.AST) -> str:
    if isinstance(parent, ast.Assign) and parent.targets:
        return _target_name(parent.targets[0])
    if isinstance(parent, ast.AnnAssign):
        return _target_name(parent.target)
    return ""


def _target_name(target: ast.AST) -> str:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return ""


def _agent_id(node: ast.Call, fallback: str) -> str:
    value = _keyword_string(node, ["id", "name", "role"])
    return _slug(value or fallback or "framework-agent")


def _keyword_string(node: ast.Call, names: list[str]) -> str:
    for keyword in node.keywords:
        if keyword.arg in names:
            value = _literal_string(keyword.value)
            if value:
                return value
    return ""


def _literal_string(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _dotted_name(node)
    if isinstance(node, ast.Call):
        return _dotted_name(node.func) or "tool"
    return ""


def _extract_tool_names(node: ast.Call, keyword_names: tuple[str, ...]) -> list[str]:
    names: list[str] = []
    for keyword in node.keywords:
        if keyword.arg not in keyword_names:
            continue
        names.extend(_names_from_value(keyword.value))
    return [name for name in dict.fromkeys(names) if name]


def _names_from_value(node: ast.AST) -> list[str]:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        names: list[str] = []
        for item in node.elts:
            names.extend(_names_from_value(item))
        return names
    if isinstance(node, ast.Dict):
        return [_literal_string(key) for key in node.keys if key is not None and _literal_string(key)]
    value = _literal_string(node)
    return [value] if value else []


def _tool(name: str, description: str, source_file: str, server_id: str) -> dict[str, Any]:
    risk_tags, risk_confidence = infer_risk_tags(name, description)
    return {
        "id": name,
        "name": name,
        "description": description,
        "risk_tags": risk_tags,
        "risk_confidence": risk_confidence,
        "risk_source": "inferred" if risk_tags else "unknown",
        "target_system": infer_target_system(f"{name} {description}"),
        "server_id": server_id,
        "source_file": source_file,
        "raw": {"collector": "framework_code_static", "name": name},
    }


def _parse_crewai_config(root: Path) -> dict[str, Any]:
    if root.is_file():
        return {"agents": [], "tools": [], "warnings": []}
    agents_file = root / "config" / "agents.yaml"
    if not agents_file.exists():
        agents_file = root / "src" / root.name.replace("-", "_") / "config" / "agents.yaml"
    if not agents_file.exists():
        return {"agents": [], "tools": [], "warnings": []}
    parsed = _simple_yaml_mapping(agents_file)
    agents = []
    tools_by_name: dict[str, dict[str, Any]] = {}
    for agent_id, config in parsed.items():
        if not isinstance(config, dict):
            continue
        tool_names = [str(item) for item in config.get("tools", []) if item]
        for tool_name in tool_names:
            tools_by_name.setdefault(tool_name, _tool(tool_name, "CrewAI YAML tool reference", str(agents_file), "framework-code:crewai"))
        agents.append(
            {
                "id": _slug(agent_id),
                "name": str(config.get("role") or agent_id),
                "runtime": "crewai",
                "environment": "unknown",
                "autonomy": "unknown",
                "tools": sorted(set(tool_names)),
                "input_sources": [DEFAULT_INPUT_SOURCE["id"]],
                "identities": [],
                "labels": {"framework": "crewai", "framework_name": "CrewAI", "collector": "framework_code_static"},
            }
        )
    return {"agents": agents, "tools": list(tools_by_name.values()), "warnings": []}


def _simple_yaml_mapping(path: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    current = ""
    current_list = ""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return result
    for raw_line in lines:
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = line.strip()
        if indent == 0 and stripped.endswith(":"):
            current = stripped[:-1].strip().strip("'\"")
            result.setdefault(current, {})
            current_list = ""
            continue
        if not current:
            continue
        if stripped.startswith("- ") and current_list:
            result[current].setdefault(current_list, []).append(stripped[2:].strip().strip("'\""))
            continue
        key, separator, value = stripped.partition(":")
        if not separator:
            continue
        key = key.strip()
        value = value.strip().strip("'\"")
        if value == "":
            result[current].setdefault(key, [])
            current_list = key
        elif value.startswith("[") and value.endswith("]"):
            result[current][key] = [item.strip().strip("'\"") for item in value[1:-1].split(",") if item.strip()]
            current_list = ""
        else:
            result[current][key] = value
            current_list = ""
    return result


def _dedupe_agents(agents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for agent in agents:
        agent_id = agent.get("id", "")
        if not agent_id:
            continue
        if agent_id not in deduped:
            deduped[agent_id] = agent
            continue
        existing = deduped[agent_id]
        existing["tools"] = sorted(set(existing.get("tools", []) + agent.get("tools", [])))
        if existing.get("runtime") == "unknown" and agent.get("runtime"):
            existing["runtime"] = agent["runtime"]
    return list(deduped.values())


def _slug(value: str) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9_.-]+", "-", text)
    text = text.strip("-._")
    return text or "framework-agent"
