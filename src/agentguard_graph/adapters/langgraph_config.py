"""Read-only collector for LangGraph application configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..schemas import load_json_file, source_name, string_list


def parse_langgraph_config(path: str | Path) -> dict[str, Any]:
    """Extract graph declarations from a local langgraph.json file.

    LangGraph configuration declares graph entrypoints and dependencies, but it
    generally does not enumerate runtime tools or identity permissions. The
    collector preserves the graph metadata and reports that limitation.
    """
    data = load_json_file(path)
    source = source_name(path)
    graphs = []
    warnings = []
    raw_graphs = data.get("graphs", {})
    if isinstance(raw_graphs, dict):
        for graph_id, entrypoint in raw_graphs.items():
            entrypoint_value = _entrypoint(entrypoint)
            if not str(graph_id):
                warnings.append(f"{source}: graph declaration has empty id")
            if not entrypoint_value:
                warnings.append(f"{source}: graph {graph_id} has empty entrypoint")
            graphs.append({"id": str(graph_id), "entrypoint": entrypoint_value})
    elif isinstance(raw_graphs, list):
        for index, item in enumerate(raw_graphs):
            if isinstance(item, dict):
                graph_id = str(item.get("id") or item.get("name") or f"graph-{index + 1}")
                entrypoint_value = _entrypoint(item.get("path") or item.get("entrypoint"))
                if not entrypoint_value:
                    warnings.append(f"{source}: graph {graph_id} has empty entrypoint")
                graphs.append({"id": graph_id, "entrypoint": entrypoint_value})
            else:
                warnings.append(f"{source}: graphs[{index}] must be an object")
    else:
        warnings.append(f"{source}: graphs must be an object or list")

    env = data.get("env", {})
    if isinstance(env, dict):
        env_keys = sorted(str(key) for key in env.keys())
    elif isinstance(env, str):
        env_keys = [env]
    elif isinstance(env, list):
        env_keys = string_list(env)
    elif env not in ({}, [], None):
        warnings.append(f"{source}: env must be an object, string, or list")
        env_keys = []

    if not graphs:
        warnings.append(f"{source}: no LangGraph graph declarations found")
    else:
        warnings.append(
            f"{source}: LangGraph config declares graph entrypoints but not tool descriptors or identity permissions"
        )
    return {
        "source_file": source,
        "graphs": graphs,
        "dependencies": _dependencies(data.get("dependencies"), source, warnings),
        "env_keys": env_keys,
        "warnings": warnings,
    }


def _entrypoint(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return str(value.get("path") or value.get("entrypoint") or value.get("module") or "")
    return ""


def _dependencies(value: Any, source: str, warnings: list[str]) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, list)):
        return string_list(value)
    warnings.append(f"{source}: dependencies must be a string or list")
    return []
