"""Optional OpenAPI 3.x JSON evidence adapter."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..errors import EvidenceLoadError
from ..schemas import infer_target_system, load_json_file, source_name
from .mcp import infer_risk_tags

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
WRITE_METHODS = {"post", "put", "patch", "delete"}
FINANCIAL_HINTS = {"refund", "payment", "invoice", "charge"}
EXTERNAL_HINTS = {"email", "message", "slack", "webhook"}
SENSITIVE_HINTS = {"customer", "contact", "account", "user", "profile"}
PRODUCTION_HINTS = {"deploy", "terraform", "kubernetes"}
SECRET_HINTS = {"secret", "token", "credential"}
SEND_HINTS = {"send"}
CREATE_HINTS = {"create"}
DELETE_HINTS = {"delete", "destroy", "remove"}
UPDATE_HINTS = {"update", "apply", "patch"}
EXECUTE_HINTS = {"execute", "exec", "run"}
DATA_CLASS_HINTS = {
    "customer_pii": {"customer", "contact", "email", "phone", "address", "ssn", "user", "profile", "name"},
    "employee_pii": {"employee", "payroll", "hr"},
    "billing_data": {"billing", "invoice", "payment", "card", "charge", "refund", "subscription"},
    "financial_data": {"transaction", "ledger", "balance", "amount", "payout"},
    "health_data": {"health", "medical", "patient", "diagnosis"},
    "secrets": {"secret", "token", "credential", "password", "apikey", "api_key"},
    "source_code": {"source", "repo", "repository", "code", "commit", "branch", "diff"},
    "production_config": {"production", "deploy", "terraform", "kubernetes", "k8s", "config"},
    "security_logs": {"audit", "log", "logs", "siem", "alert", "incident"},
}


def _words(text: str) -> set[str]:
    split_camel = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    normalized = "".join(character.lower() if character.isalnum() else " " for character in split_camel)
    return {part for part in normalized.split() if part}


def _extract_security_scopes(security: Any) -> list[str]:
    scopes: list[str] = []
    if not isinstance(security, list):
        return scopes
    for requirement in security:
        if not isinstance(requirement, dict):
            continue
        for scheme, values in requirement.items():
            if isinstance(values, list):
                scopes.extend(f"{scheme}:{value}" for value in values)
            else:
                scopes.append(str(scheme))
    return sorted(set(str(scope) for scope in scopes if scope))


def _schema_terms(value: Any, depth: int = 0) -> list[str]:
    if depth > 8:
        return []
    terms: list[str] = []
    if isinstance(value, dict):
        ref = value.get("$ref")
        if isinstance(ref, str):
            terms.append(ref.rsplit("/", 1)[-1])
        for key in ("title", "description", "format", "type"):
            if value.get(key) is not None:
                terms.append(str(value[key]))
        properties = value.get("properties")
        if isinstance(properties, dict):
            for property_name, property_schema in properties.items():
                terms.append(str(property_name))
                terms.extend(_schema_terms(property_schema, depth + 1))
        for key in ("items", "additionalProperties", "schema"):
            terms.extend(_schema_terms(value.get(key), depth + 1))
        for key in ("allOf", "anyOf", "oneOf"):
            items = value.get(key)
            if isinstance(items, list):
                for item in items:
                    terms.extend(_schema_terms(item, depth + 1))
        required = value.get("required")
        if isinstance(required, list):
            terms.extend(str(item) for item in required if item is not None)
        handled = {
            "$ref",
            "title",
            "description",
            "format",
            "type",
            "properties",
            "items",
            "additionalProperties",
            "schema",
            "allOf",
            "anyOf",
            "oneOf",
            "required",
        }
        for key, nested in value.items():
            if key in handled or key in {"example", "examples"}:
                continue
            terms.append(str(key))
            terms.extend(_schema_terms(nested, depth + 1))
    elif isinstance(value, list):
        for item in value:
            terms.extend(_schema_terms(item, depth + 1))
    return terms


def _infer_data_classes(text: str) -> list[str]:
    words = _words(text)
    compact = "".join(character.lower() if character.isalnum() else "_" for character in text)
    classes: set[str] = set()
    for data_class, hints in DATA_CLASS_HINTS.items():
        if words.intersection(hints) or any(hint in compact for hint in hints if "_" in hint):
            classes.add(data_class)
    return sorted(classes)


def _operation_data_classes(operation: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    request_terms = _schema_terms(operation.get("requestBody", {}))
    response_terms = _schema_terms(operation.get("responses", {}))
    request_classes = _infer_data_classes(" ".join(request_terms))
    response_classes = _infer_data_classes(" ".join(response_terms))
    return request_classes, response_classes, sorted(set(request_classes + response_classes))


def _operation_risk(
    method: str,
    api_path: str,
    operation_id: str,
    summary: str,
    description: str,
    security_scopes: list[str],
    data_classes: list[str],
) -> tuple[list[str], str]:
    text = f"{operation_id} {api_path} {summary} {description} {' '.join(security_scopes)}"
    words = _words(text)
    risk_tags, risk_confidence = infer_risk_tags(operation_id, text)
    tags = set(risk_tags)

    is_write = method in WRITE_METHODS or bool(words.intersection(CREATE_HINTS | DELETE_HINTS | UPDATE_HINTS))
    if is_write:
        tags.add("write_action")
        risk_confidence = "medium"
    if method == "get" and not is_write:
        tags.add("read_action")

    if words.intersection(FINANCIAL_HINTS):
        tags.add("financial_action")
        risk_confidence = "medium"
    if words.intersection(EXTERNAL_HINTS) or words.intersection(SEND_HINTS):
        tags.add("external_message")
        risk_confidence = "medium"
    if words.intersection(SENSITIVE_HINTS):
        tags.add("sensitive_write" if is_write else "sensitive_read")
        risk_confidence = "medium"
    if set(data_classes).intersection({"customer_pii", "employee_pii", "billing_data", "health_data", "financial_data"}):
        tags.add("sensitive_write" if is_write else "sensitive_read")
        risk_confidence = "medium"
    if set(data_classes).intersection({"billing_data", "financial_data"}):
        tags.add("financial_action")
        risk_confidence = "medium"
    if "secrets" in data_classes:
        tags.add("secret_access")
        risk_confidence = "medium"
    if words.intersection(PRODUCTION_HINTS):
        tags.add("production_write")
        risk_confidence = "medium"
    if words.intersection(SECRET_HINTS):
        tags.add("secret_access")
        risk_confidence = "medium"
    if words.intersection(EXECUTE_HINTS):
        tags.add("command_execution")
        risk_confidence = "medium"
    if words.intersection(DELETE_HINTS):
        tags.add("destructive_action")
        risk_confidence = "medium"

    return sorted(tags), risk_confidence


def parse_openapi(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {"tools": [], "source_file": None, "warnings": []}
    root = Path(path)
    if root.suffix.lower() in {".yaml", ".yml"}:
        raise EvidenceLoadError(f"{root}: OpenAPI YAML input is not supported in v0.1; provide JSON OpenAPI evidence")
    files = sorted(root.glob("*.json")) if root.is_dir() else [root]
    tools: list[dict[str, Any]] = []
    warnings: list[str] = []
    if root.is_dir():
        for yaml_path in sorted([*root.glob("*.yaml"), *root.glob("*.yml")]):
            warnings.append(f"{source_name(yaml_path)}: OpenAPI YAML input is not supported; skipped")
        if not files:
            warnings.append(f"{source_name(root)}: no JSON OpenAPI files found")
    for file_path in files:
        try:
            data = load_json_file(file_path)
        except EvidenceLoadError as exc:
            if root.is_dir():
                warnings.append(f"{source_name(file_path)}: skipped invalid OpenAPI JSON: {exc}")
                continue
            raise
        source = source_name(file_path)
        if not str(data.get("openapi", "")).startswith("3."):
            warnings.append(f"{source}: OpenAPI version is not 3.x or is missing")
        info = data.get("info", {}) if isinstance(data.get("info"), dict) else {}
        api_title = str(info.get("title") or source)
        api_version = str(info.get("version") or "")
        root_security = data.get("security", [])
        server_urls = [
            str(server.get("url"))
            for server in data.get("servers", [])
            if isinstance(server, dict) and server.get("url")
        ]
        api_source = {
            "id": source,
            "title": api_title,
            "version": api_version,
            "source_file": source,
            "server_urls": server_urls,
        }
        paths = data.get("paths", {})
        if paths is None:
            paths = {}
        if not isinstance(paths, dict):
            warnings.append(f"{source}: OpenAPI paths must be an object")
            continue
        for api_path, path_item in paths.items():
            if not isinstance(path_item, dict):
                warnings.append(f"{source}: OpenAPI path {api_path} must be an object")
                continue
            for method, operation in path_item.items():
                if method.lower() not in HTTP_METHODS:
                    continue
                if not isinstance(operation, dict):
                    warnings.append(f"{source}: OpenAPI operation {method.upper()} {api_path} must be an object")
                    continue
                method_lower = method.lower()
                operation_id = str(operation.get("operationId") or f"{method}_{api_path}".replace("/", "_"))
                summary = str(operation.get("summary", ""))
                description = str(operation.get("description", ""))
                security = operation.get("security", root_security)
                security_scopes = _extract_security_scopes(security)
                request_data_classes, response_data_classes, data_classes = _operation_data_classes(operation)
                risk_tags, risk_confidence = _operation_risk(
                    method_lower,
                    api_path,
                    operation_id,
                    summary,
                    description,
                    security_scopes,
                    data_classes,
                )
                tools.append(
                    {
                        "id": operation_id,
                        "name": operation_id,
                        "description": summary or description,
                        "method": method_lower.upper(),
                        "path": api_path,
                        "security": security,
                        "security_scopes": security_scopes,
                        "server_urls": server_urls,
                        "api_document_id": source,
                        "api_source_id": f"{source}:{operation_id}",
                        "api_title": api_title,
                        "api_version": api_version,
                        "api_source": api_source,
                        "request_data_classes": request_data_classes,
                        "response_data_classes": response_data_classes,
                        "data_classes": data_classes,
                        "risk_tags": risk_tags,
                        "risk_confidence": risk_confidence,
                        "risk_source": "inferred",
                        "target_system": infer_target_system(f"{operation_id} {api_path} {' '.join(server_urls)}"),
                        "source_file": source,
                        "raw": operation,
                    }
                )
    return {"tools": tools, "source_file": str(root), "warnings": warnings}
