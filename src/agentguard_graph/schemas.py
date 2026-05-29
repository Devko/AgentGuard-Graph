"""Shared schema constants and safe JSON loading helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import EvidenceLoadError

SCHEMA_VERSION = "0.1"

CONFIDENCE_VALUES = {"high", "medium", "low"}
AUTONOMY_VALUES = {"suggestion_only", "approval_required", "autonomous", "unknown"}
ENVIRONMENT_VALUES = {"production", "staging", "development", "local", "unknown"}
SENSITIVITY_VALUES = {"public", "internal", "medium", "high", "critical", "unknown"}
DECISION_VALUES = {"allow", "approval_required", "deny", "unknown", "blocked"}
CONTROL_TAGS = {
    "sandbox_control",
    "egress_allowlist",
    "scoped_identity",
    "read_only_identity",
    "command_allowlist",
    "secret_denylist",
    "amount_threshold",
    "audit_logging",
    "change_ticket_required",
    "dlp_redaction",
}

RISK_TAGS = {
    "sensitive_read",
    "sensitive_write",
    "external_message",
    "data_exfiltration_sink",
    "financial_action",
    "production_write",
    "command_execution",
    "filesystem_read",
    "filesystem_write",
    "secret_access",
    "network_access",
    "code_write",
    "repository_write",
    "ci_cd_write",
    "infrastructure_write",
    "destructive_action",
    "memory_read",
    "memory_write",
    "read_action",
    "write_action",
}

NODE_TYPES = {
    "agent",
    "runtime",
    "model",
    "prompt",
    "tool",
    "mcp_server",
    "api_definition",
    "api_operation",
    "identity",
    "permission",
    "data_source",
    "memory_store",
    "input_source",
    "external_sink",
    "approval_policy",
    "runtime_event",
    "finding",
    "unknown",
}

EDGE_TYPES = {
    "agent_uses_tool",
    "agent_runs_as_identity",
    "tool_bound_to_identity",
    "identity_has_permission",
    "permission_reaches_data",
    "tool_reads_data",
    "tool_writes_data",
    "tool_sends_external",
    "tool_executes_command",
    "tool_modifies_production",
    "agent_receives_input",
    "agent_has_memory",
    "action_requires_approval",
    "approval_missing",
    "approval_present",
    "event_observed",
    "event_blocked",
    "event_allowed",
    "tool_defined_by_mcp_server",
    "api_defines_tool",
    "missing_evidence",
}

SENSITIVE_DATA_CLASSES = {
    "customer_pii",
    "employee_pii",
    "billing_data",
    "health_data",
    "secrets",
    "source_code",
    "production_config",
    "security_logs",
    "financial_data",
}

DANGEROUS_TAGS = {
    "command_execution",
    "filesystem_write",
    "secret_access",
    "production_write",
    "infrastructure_write",
    "ci_cd_write",
    "repository_write",
    "destructive_action",
}

TARGET_HINTS = {
    "salesforce": "salesforce",
    "github": "github",
    "git": "github",
    "gmail": "google_workspace",
    "google": "google_workspace",
    "azure": "azure",
    "entra": "microsoft_365",
    "graph": "microsoft_365",
    "microsoft 365": "microsoft_365",
    "microsoft365": "microsoft_365",
    "m365": "microsoft_365",
    "copilot": "microsoft_365",
    "graph.microsoft": "microsoft_365",
    "sharepoint": "microsoft_365",
    "onedrive": "microsoft_365",
    "teams": "microsoft_365",
    "outlook": "microsoft_365",
    "dataverse": "dataverse",
    "power platform": "power_platform",
    "powerplatform": "power_platform",
    "slack": "slack",
    "aws": "aws",
    "gcp": "gcp",
    "google cloud": "gcp",
    "kubernetes": "kubernetes",
    "k8s": "kubernetes",
    "okta": "okta",
    "jira": "jira",
    "confluence": "confluence",
    "servicenow": "servicenow",
    "service now": "servicenow",
    "datadog": "datadog",
    "pagerduty": "pagerduty",
    "snowflake": "snowflake",
    "databricks": "databricks",
    "stripe": "stripe",
    "netsuite": "netsuite",
    "zendesk": "zendesk",
}


def load_json_file(path: str | Path, required: bool = True) -> dict[str, Any]:
    evidence_path = Path(path)
    if not evidence_path.exists():
        if required:
            raise EvidenceLoadError(f"{evidence_path}: file not found")
        return {}
    try:
        with evidence_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise EvidenceLoadError(f"{evidence_path}:{exc.lineno}:{exc.colno}: invalid JSON: {exc.msg}") from exc
    except UnicodeDecodeError as exc:
        raise EvidenceLoadError(f"{evidence_path}: cannot decode as UTF-8: {exc.reason}") from exc
    except OSError as exc:
        raise EvidenceLoadError(f"{evidence_path}: cannot read file: {exc}") from exc
    if not isinstance(data, dict):
        raise EvidenceLoadError(f"{evidence_path}: top-level JSON value must be an object")
    return data


def load_jsonl_file(path: str | Path, required: bool = True) -> list[dict[str, Any]]:
    evidence_path = Path(path)
    if not evidence_path.exists():
        if required:
            raise EvidenceLoadError(f"{evidence_path}: file not found")
        return []
    events: list[dict[str, Any]] = []
    try:
        with evidence_path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    item = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise EvidenceLoadError(
                        f"{evidence_path}:{line_no}:{exc.colno}: invalid JSONL: {exc.msg}"
                    ) from exc
                if not isinstance(item, dict):
                    raise EvidenceLoadError(f"{evidence_path}:{line_no}: JSONL line must be an object")
                events.append(item)
    except UnicodeDecodeError as exc:
        raise EvidenceLoadError(f"{evidence_path}: cannot decode as UTF-8: {exc.reason}") from exc
    except OSError as exc:
        raise EvidenceLoadError(f"{evidence_path}: cannot read file: {exc}") from exc
    return events


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def string_list(value: Any) -> list[str]:
    return [str(item) for item in as_list(value) if item is not None]


def source_name(path: str | Path | None) -> str:
    return Path(path).name if path else "unknown"


def node_id(node_type: str, value: str) -> str:
    return f"{node_type}:{value}"


def edge_id(edge_type: str, from_node: str, to_node: str) -> str:
    safe_from = from_node.replace(":", "_")
    safe_to = to_node.replace(":", "_")
    return f"{edge_type}:{safe_from}->{safe_to}"


def infer_target_system(text: str) -> str:
    lowered = text.lower()
    for hint, target in TARGET_HINTS.items():
        if hint in lowered:
            return target
    return "unknown"
