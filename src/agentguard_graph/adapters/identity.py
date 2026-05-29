"""Adapter for identity and permission evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..schemas import load_json_file, source_name, string_list


def parse_identity(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {"schema_version": "0.1", "identities": [], "source_file": None, "warnings": []}
    data = load_json_file(path)
    source = source_name(path)
    warnings = []
    identities = []
    for index, item in enumerate(_list_value(data, "identities", source, warnings)):
        if not isinstance(item, dict):
            warnings.append(f"{source}: identities[{index}] must be an object")
            continue
        identity_id = str(item.get("id", ""))
        if not identity_id:
            warnings.append(f"{source}: identities[{index}] is missing id")
        if item.get("scopes") is not None and not isinstance(item.get("scopes"), list):
            warnings.append(f"{source}: identity {identity_id or index} scopes should be a list")
        identity_confidence = str(item.get("confidence", "medium"))
        permissions = []
        raw_permissions = item.get("permissions", [])
        if raw_permissions is None:
            raw_permissions = []
        elif not isinstance(raw_permissions, list):
            warnings.append(f"{source}: identity {identity_id or index} permissions must be a list")
            raw_permissions = []
        for permission_index, permission in enumerate(raw_permissions):
            if not isinstance(permission, dict):
                warnings.append(f"{source}: identity {identity_id or index} permissions[{permission_index}] must be an object")
                continue
            if not permission.get("resource"):
                warnings.append(f"{source}: identity {identity_id or index} permissions[{permission_index}] is missing resource")
            for field in ["actions", "data_classes"]:
                if permission.get(field) is not None and not isinstance(permission.get(field), list):
                    warnings.append(
                        f"{source}: identity {identity_id or index} permission {permission_index} {field} should be a list"
                    )
            permissions.append(
                {
                    "resource": str(permission.get("resource", "")),
                    "actions": string_list(permission.get("actions")),
                    "data_classes": string_list(permission.get("data_classes")),
                    "confidence": str(permission.get("confidence", identity_confidence)),
                    "raw": permission,
                }
            )
        identities.append(
            {
                "id": identity_id,
                "type": str(item.get("type", "unknown")),
                "target_system": str(item.get("target_system", "unknown")),
                "scopes": string_list(item.get("scopes")),
                "permissions": permissions,
                "confidence": identity_confidence,
                "raw_source": item.get("raw_source"),
                "source_file": source,
                "raw": item,
            }
        )
    return {
        "schema_version": str(data.get("schema_version", "0.1")),
        "identities": identities,
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
