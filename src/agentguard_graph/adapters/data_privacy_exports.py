"""Import common data classification JSON exports into data catalog records."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..errors import EvidenceLoadError
from ..schemas import SENSITIVITY_VALUES, infer_target_system, source_name, string_list


INFO_TYPE_CLASSES = {
    "api_key": "secrets",
    "aws_credentials": "secrets",
    "azure_client_secret": "secrets",
    "bank_account": "billing_data",
    "cardholder": "payment_data",
    "credit_card": "payment_data",
    "customer": "customer_pii",
    "customer_id": "customer_pii",
    "email": "customer_pii",
    "employee": "employee_pii",
    "financial": "financial_data",
    "github_token": "secrets",
    "health": "health_data",
    "iban": "billing_data",
    "medical": "health_data",
    "passport": "customer_pii",
    "password": "secrets",
    "payment": "payment_data",
    "pci": "payment_data",
    "person": "customer_pii",
    "phi": "health_data",
    "pii": "customer_pii",
    "secret": "secrets",
    "social_security": "customer_pii",
    "source_code": "source_code",
    "ssn": "customer_pii",
    "token": "secrets",
}

SENSITIVITY_HINTS = {
    "critical": "critical",
    "highly confidential": "critical",
    "high": "high",
    "restricted": "critical",
    "confidential": "high",
    "sensitive": "high",
    "private": "high",
    "medium": "medium",
    "internal": "internal",
    "low": "internal",
    "public": "public",
}


def parse_data_catalog_export(path: str | Path) -> dict[str, Any]:
    data, source = _load_privacy_json(path)
    records = _records(data, ["data_sources", "assets", "datasets", "tables", "objects", "entities", "resources", "items", "records"])
    return _result("data_catalog_export", source, [_source_from_catalog(item, source, index) for index, item in enumerate(records, start=1)])


def parse_dlp_export(path: str | Path) -> dict[str, Any]:
    data, source = _load_privacy_json(path)
    records = _records(data, ["findings", "dlp_findings", "inspection_results", "matches", "items", "records"])
    return _result("dlp_export", source, [_source_from_dlp(item, source, index) for index, item in enumerate(records, start=1)])


def parse_sensitivity_label_export(path: str | Path) -> dict[str, Any]:
    data, source = _load_privacy_json(path)
    records = _records(data, ["labels", "sensitivityLabels", "labeledResources", "files", "items", "records"])
    return _result("sensitivity_label_export", source, [_source_from_sensitivity_label(item, source, index) for index, item in enumerate(records, start=1)])


def parse_table_classification_export(path: str | Path) -> dict[str, Any]:
    data, source = _load_privacy_json(path)
    records = _records(data, ["tables", "columns", "objects", "classifications", "dataSources", "items", "records"])
    return _result("table_classification_export", source, [_source_from_table_classification(item, source, index) for index, item in enumerate(records, start=1)])


def _load_privacy_json(path: str | Path) -> tuple[Any, str]:
    export_path = Path(path)
    if not export_path.exists():
        raise EvidenceLoadError(f"{export_path}: data classification export file not found")
    try:
        data = json.loads(export_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EvidenceLoadError(f"{export_path}:{exc.lineno}:{exc.colno}: invalid JSON: {exc.msg}") from exc
    except UnicodeDecodeError as exc:
        raise EvidenceLoadError(f"{export_path}: cannot decode as UTF-8: {exc.reason}") from exc
    except OSError as exc:
        raise EvidenceLoadError(f"{export_path}: cannot read file: {exc}") from exc
    if not isinstance(data, (dict, list)):
        raise EvidenceLoadError(f"{export_path}: data classification export must be a JSON object or array")
    return data, source_name(export_path)


def _result(kind: str, source: str, data_sources: list[dict[str, Any]]) -> dict[str, Any]:
    clean_sources = [item for item in data_sources if item]
    warnings = []
    if not clean_sources:
        warnings.append(f"{source}: no data sources were extracted from {kind}")
    return {"kind": kind, "source_file": source, "data_sources": clean_sources, "warnings": warnings}


def _records(data: Any, keys: list[str]) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = _records(value, keys)
            if nested:
                return nested
    for key, value in data.items():
        if isinstance(value, list) and key.lower() in {item.lower() for item in keys}:
            return [item for item in value if isinstance(item, dict)]
    return [data]


def _source_from_catalog(item: dict[str, Any], source: str, index: int) -> dict[str, Any]:
    fields = _fields(item)
    labels = _labels(item)
    text = _classification_text(item, fields)
    data_source_id = _resource_id(item, index)
    return _data_source(
        source_kind="data_catalog_export",
        source=source,
        index=index,
        raw=item,
        data_source_id=data_source_id,
        name=_first(item, "name", "displayName", "title", "assetName", "table", "object") or data_source_id,
        target_system=_first(item, "target_system", "system", "platform", "source", "service", "type") or infer_target_system(data_source_id),
        data_classes=_data_classes(item, text),
        sensitivity=_sensitivity(item, labels, text),
        owner=_first(item, "owner", "data_owner", "steward", "businessOwner"),
        labels=labels,
        fields=fields,
    )


def _source_from_dlp(item: dict[str, Any], source: str, index: int) -> dict[str, Any]:
    info_type = _info_type(item)
    field = _first(item, "field", "field_name", "column", "column_name", "property")
    resource = _resource_id(item, index, allow_generated=False)
    data_source_id = ".".join(part for part in [resource, field] if part) or f"dlp:{source}:{index}"
    text = _classification_text(item, [])
    return _data_source(
        source_kind="dlp_export",
        source=source,
        index=index,
        raw=item,
        data_source_id=data_source_id,
        name=_first(item, "name", "resource", "resourceName", "table", "object") or data_source_id,
        target_system=_first(item, "target_system", "system", "platform", "service") or infer_target_system(data_source_id),
        data_classes=_data_classes(item, f"{text} {info_type}"),
        sensitivity=_sensitivity(item, [info_type], text),
        owner=_first(item, "owner", "data_owner", "steward"),
        labels=[info_type] if info_type else _labels(item),
        fields=_fields(item),
    )


def _source_from_sensitivity_label(item: dict[str, Any], source: str, index: int) -> dict[str, Any]:
    label = _first(item, "label", "labelName", "sensitivityLabel", "sensitivity_label", "classification")
    label_obj = item.get("label") if isinstance(item.get("label"), dict) else item.get("sensitivityLabel") if isinstance(item.get("sensitivityLabel"), dict) else {}
    if label_obj:
        label = _first(label_obj, "name", "displayName", "id") or label
    data_source_id = _resource_id(item, index)
    labels = _labels(item) or ([label] if label else [])
    text = _classification_text(item, [])
    return _data_source(
        source_kind="sensitivity_label_export",
        source=source,
        index=index,
        raw=item,
        data_source_id=data_source_id,
        name=_first(item, "name", "displayName", "fileName", "resourceName") or data_source_id,
        target_system=_first(item, "target_system", "system", "platform", "service") or infer_target_system(data_source_id),
        data_classes=_data_classes(item, f"{text} {label}"),
        sensitivity=_sensitivity(item, labels, text),
        owner=_first(item, "owner", "data_owner", "steward"),
        labels=labels,
        fields=[],
    )


def _source_from_table_classification(item: dict[str, Any], source: str, index: int) -> dict[str, Any]:
    fields = _fields(item)
    table = _table_name(item)
    data_source_id = table or _resource_id(item, index)
    labels = _labels(item)
    text = _classification_text(item, fields)
    return _data_source(
        source_kind="table_classification_export",
        source=source,
        index=index,
        raw=item,
        data_source_id=data_source_id,
        name=_first(item, "name", "table", "table_name", "object", "object_name") or data_source_id,
        target_system=_first(item, "target_system", "system", "platform", "database_type", "service") or infer_target_system(data_source_id),
        data_classes=_data_classes(item, text),
        sensitivity=_sensitivity(item, labels, text),
        owner=_first(item, "owner", "data_owner", "steward"),
        labels=labels,
        fields=fields,
    )


def _data_source(
    *,
    source_kind: str,
    source: str,
    index: int,
    raw: dict[str, Any],
    data_source_id: str,
    name: str,
    target_system: str,
    data_classes: list[str],
    sensitivity: str,
    owner: str,
    labels: list[str],
    fields: list[dict[str, Any]],
) -> dict[str, Any]:
    data_source_id = data_source_id or _stable_id(source_kind, raw)
    return {
        "id": data_source_id,
        "name": name or data_source_id,
        "target_system": target_system or infer_target_system(data_source_id),
        "data_classes": sorted(set(data_classes)),
        "sensitivity": sensitivity if sensitivity in SENSITIVITY_VALUES else "unknown",
        "persistence": str(raw.get("persistence", "unknown")),
        "owner": owner,
        "classification_labels": sorted(set(label for label in labels if label)),
        "fields": fields,
        "source_kind": source_kind,
        "source_file": source,
        "source_evidence": f"{source}:{index}",
        "raw": raw,
    }


def _resource_id(item: dict[str, Any], index: int, *, allow_generated: bool = True) -> str:
    table = _table_name(item)
    value = _first(
        item,
        "id",
        "qualifiedName",
        "qualified_name",
        "resource",
        "resourceName",
        "resource_name",
        "object",
        "objectName",
        "object_name",
        "asset",
        "assetName",
        "path",
        "file",
        "fileName",
    ) or table
    return value or (f"classification:{index}" if allow_generated else "")


def _table_name(item: dict[str, Any]) -> str:
    table = _first(item, "table", "table_name", "tableName", "object", "object_name", "objectName", "entity")
    database = _first(item, "database", "dataset", "schema", "namespace")
    return ".".join(part for part in [database, table] if part)


def _fields(item: dict[str, Any]) -> list[dict[str, Any]]:
    raw_fields = item.get("fields") or item.get("columns") or item.get("attributes") or []
    if isinstance(raw_fields, dict):
        raw_fields = [{"name": key, **(value if isinstance(value, dict) else {"classification": value})} for key, value in raw_fields.items()]
    if not isinstance(raw_fields, list):
        return []
    fields = []
    for field in raw_fields:
        if not isinstance(field, dict):
            continue
        name = _first(field, "name", "field", "field_name", "column", "column_name", "property")
        labels = _labels(field)
        text = _classification_text(field, [])
        fields.append(
            {
                "name": name,
                "data_classes": _data_classes(field, text),
                "sensitivity": _sensitivity(field, labels, text),
                "classification_labels": labels,
            }
        )
    return fields


def _labels(item: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ["classification", "classifications", "label", "labels", "tag", "tags", "glossary_terms", "infoType", "info_type"]:
        value = item.get(key)
        if isinstance(value, dict):
            values.extend(string_list(value.get("name") or value.get("displayName") or value.get("id")))
        elif isinstance(value, list):
            for entry in value:
                if isinstance(entry, dict):
                    values.extend(string_list(entry.get("name") or entry.get("displayName") or entry.get("id")))
                else:
                    values.extend(string_list(entry))
        else:
            values.extend(string_list(value))
    return [value for value in values if value]


def _classification_text(item: dict[str, Any], fields: list[dict[str, Any]]) -> str:
    parts = []
    for key in [
        "id",
        "name",
        "qualifiedName",
        "resource",
        "resourceName",
        "table",
        "object",
        "classification",
        "classifications",
        "label",
        "labels",
        "data_classes",
        "infoType",
        "info_type",
        "findingType",
    ]:
        value = item.get(key)
        if value is not None:
            parts.append(json.dumps(value, default=str))
    for field in fields:
        parts.extend(field.get("classification_labels", []))
        parts.extend(field.get("data_classes", []))
    return " ".join(parts).lower()


def _data_classes(item: dict[str, Any], text: str) -> list[str]:
    classes = string_list(item.get("data_classes") or item.get("dataClassifications"))
    for label in _labels(item):
        classes.extend(_classes_from_text(label))
    classes.extend(_classes_from_text(text))
    return sorted(set(classes))


def _classes_from_text(text: str) -> list[str]:
    lowered = str(text or "").lower().replace("-", "_").replace(" ", "_")
    classes = []
    for hint, data_class in INFO_TYPE_CLASSES.items():
        if hint in lowered:
            classes.append(data_class)
    return classes


def _sensitivity(item: dict[str, Any], labels: list[str], text: str) -> str:
    explicit = str(
        item.get("sensitivity")
        or item.get("sensitivity_level")
        or item.get("confidentiality")
        or item.get("risk")
        or ""
    ).lower()
    for candidate in [explicit, *labels, text]:
        lowered = str(candidate or "").lower()
        if lowered in SENSITIVITY_VALUES:
            return lowered
        for hint, sensitivity in SENSITIVITY_HINTS.items():
            if hint in lowered:
                return sensitivity
    classes = set(_data_classes(item, text))
    if classes.intersection({"secrets", "payment_data", "health_data"}):
        return "critical"
    if classes:
        return "high"
    return "unknown"


def _info_type(item: dict[str, Any]) -> str:
    value = item.get("infoType") or item.get("info_type") or item.get("infotype")
    if isinstance(value, dict):
        return _first(value, "name", "displayName", "id")
    return str(value or item.get("findingType") or item.get("type") or "")


def _stable_id(source_kind: str, raw: dict[str, Any]) -> str:
    payload = json.dumps(raw, sort_keys=True, default=str)
    return f"{source_kind}:{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:10]}"


def _first(item: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = item.get(key)
        if value is not None and value != "":
            return str(value)
    return ""
