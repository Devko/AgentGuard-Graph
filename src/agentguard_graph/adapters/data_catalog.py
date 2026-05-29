"""Adapter for data catalog evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..schemas import SENSITIVITY_VALUES, load_json_file, source_name, string_list


def parse_data_catalog(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {"schema_version": "0.1", "data_sources": [], "source_file": None, "warnings": []}
    data = load_json_file(path)
    source = source_name(path)
    warnings = []
    data_sources = []
    for index, item in enumerate(_list_value(data, "data_sources", source, warnings)):
        if not isinstance(item, dict):
            warnings.append(f"{source}: data_sources[{index}] must be an object")
            continue
        data_source_id = str(item.get("id", ""))
        if not data_source_id:
            warnings.append(f"{source}: data_sources[{index}] is missing id")
        if item.get("data_classes") is not None and not isinstance(item.get("data_classes"), list):
            warnings.append(f"{source}: data_source {data_source_id or index} data_classes should be a list")
        sensitivity = str(item.get("sensitivity", "unknown"))
        if sensitivity not in SENSITIVITY_VALUES:
            warnings.append(f"{source}: data_source {data_source_id or index} sensitivity normalized to unknown: {sensitivity}")
        data_sources.append(
            {
                "id": data_source_id,
                "name": str(item.get("name") or item.get("id", "")),
                "target_system": str(item.get("target_system", "unknown")),
                "data_classes": string_list(item.get("data_classes")),
                "sensitivity": sensitivity if sensitivity in SENSITIVITY_VALUES else "unknown",
                "persistence": str(item.get("persistence", "unknown")),
                "owner": str(item.get("owner") or item.get("data_owner") or item.get("steward") or ""),
                "classification_labels": string_list(item.get("classification_labels") or item.get("labels") or item.get("classifications")),
                "fields": item.get("fields", []) if isinstance(item.get("fields", []), list) else [],
                "source_kind": str(item.get("source_kind") or "data_catalog"),
                "source_evidence": str(item.get("source_evidence") or source),
                "source_file": source,
                "raw": item,
            }
        )
    return {
        "schema_version": str(data.get("schema_version", "0.1")),
        "data_sources": data_sources,
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
