"""Offline-only controls analysis for AI execution-layer evidence."""

from __future__ import annotations

import json
import re
from typing import Any

from .adapters.approval_policy import evaluate_policy
from .schemas import DANGEROUS_TAGS
from .validation.validate_inputs import all_tools


REQUIRED_CONTROL_LABELS = {
    "approval_required": "matching approval or deny policy",
    "sandbox_control": "sandbox evidence",
    "command_allowlist": "command allowlist",
    "secret_denylist": "secret/path denylist",
    "egress_allowlist": "egress allowlist",
    "scoped_identity": "scoped identity",
    "read_only_identity": "read-only identity",
    "amount_threshold": "amount threshold",
    "audit_logging": "audit logging",
    "change_ticket_required": "change-ticket requirement",
    "dlp_redaction": "DLP/redaction",
}

HIGH_RISK_TAGS = DANGEROUS_TAGS | {
    "external_message",
    "data_exfiltration_sink",
    "financial_action",
    "network_access",
    "memory_write",
}

PROMPT_FIELD_HINTS = {
    "prompt",
    "system_prompt",
    "system",
    "instructions",
    "developer_instructions",
    "guardrail",
    "guardrails",
    "security_prompt",
    "policy_prompt",
    "safety_instructions",
}

PROMPT_SECURITY_PATTERNS = {
    "never reveal": re.compile(r"\bnever\s+reveal\b", re.I),
    "do not reveal": re.compile(r"\bdo\s+not\s+reveal\b", re.I),
    "do not leak": re.compile(r"\bdo\s+not\s+leak\b", re.I),
    "never leak": re.compile(r"\bnever\s+leak\b", re.I),
    "do not expose secrets": re.compile(r"\bdo\s+not\s+expose\s+secret", re.I),
    "ignore prompt injection": re.compile(r"\b(prompt\s+injection|ignore\s+malicious|ignore\s+attempts?)\b", re.I),
    "do not share credentials": re.compile(r"\b(do\s+not|never)\s+(share|print|output).{0,40}(credential|token|api\s*key|secret|password)", re.I),
}

GENERIC_NAME_PATTERNS = {
    "generic command execution": re.compile(r"(^|[._:-])(run|exec|execute|shell|terminal|bash|powershell|cmd)([._:-]|$)", re.I),
    "generic filesystem access": re.compile(r"(^|[._:-])(file|files|filesystem|workspace|path)\.(read|write|list|delete|edit)|filesystem|workspace", re.I),
    "generic network request": re.compile(r"(^|[._:-])(http|fetch|request|webhook|url|network)([._:-]|$)", re.I),
    "generic query execution": re.compile(r"(^|[._:-])(sql|query|database|db)\.(run|exec|execute|query)|run_query|execute_query", re.I),
}

SCHEMA_SELECTOR_KEYS = {
    "args",
    "cmd",
    "command",
    "customer",
    "customer_id",
    "customerid",
    "file",
    "account_id",
    "accountid",
    "path",
    "query",
    "resource_id",
    "resourceid",
    "sql",
    "tenant",
    "tenant_id",
    "tenantid",
    "ticket",
    "ticket_id",
    "ticketid",
    "uri",
    "url",
}

CONTROL_ROADMAP_GUIDANCE = {
    "approval_required": {
        "priority": "P1",
        "title": "Add approval or deny decisions for high-risk tools",
        "category": "policy",
        "evidence_needed": [
            "approval-policy.json rules that match the affected tool or risk_tag",
            "a decision of approval_required or deny for sensitive actions",
        ],
        "acceptance_criteria": [
            "Every high-risk tool has a matching approval_required or deny policy rule.",
            "The rule match uses schema-supported keys such as agent, tool, risk_tag, target_system, or environment.",
        ],
    },
    "audit_logging": {
        "priority": "P1",
        "title": "Declare audit logging for high-risk tool calls",
        "category": "audit",
        "evidence_needed": [
            "policy controls that include audit_logging",
            "a local evidence note that identifies the event fields retained for tool calls",
        ],
        "acceptance_criteria": ["High-risk tools declare audit_logging in local policy evidence."],
    },
    "sandbox_control": {
        "priority": "P1",
        "title": "Document sandbox boundaries for executable and filesystem tools",
        "category": "sandbox",
        "evidence_needed": [
            "policy controls that include sandbox_control",
            "tool descriptors or local evidence showing workspace, filesystem, timeout, and memory boundaries",
        ],
        "acceptance_criteria": ["Command, code, and filesystem tools declare sandbox_control."],
    },
    "command_allowlist": {
        "priority": "P1",
        "title": "Add command allowlists for execution tools",
        "category": "sandbox",
        "evidence_needed": [
            "policy controls that include command_allowlist",
            "tool schema or policy evidence that constrains executable commands and arguments",
        ],
        "acceptance_criteria": ["Command execution tools declare command_allowlist."],
    },
    "secret_denylist": {
        "priority": "P1",
        "title": "Keep secret paths out of AI tool reach",
        "category": "secrets",
        "evidence_needed": [
            "policy controls that include secret_denylist",
            "local evidence for denied secret paths, credential files, token stores, and environment files",
        ],
        "acceptance_criteria": ["Secret-capable, command, and filesystem tools declare secret_denylist."],
    },
    "egress_allowlist": {
        "priority": "P1",
        "title": "Declare outbound egress allowlists",
        "category": "egress",
        "evidence_needed": [
            "policy controls that include egress_allowlist",
            "local evidence naming allowed domains, APIs, or outbound destinations",
        ],
        "acceptance_criteria": ["Network and external-send tools declare egress_allowlist."],
    },
    "dlp_redaction": {
        "priority": "P1",
        "title": "Add DLP or redaction controls for outbound data",
        "category": "data_protection",
        "evidence_needed": [
            "policy controls that include dlp_redaction",
            "local evidence showing which data classes are redacted, blocked, or reviewed before external send",
        ],
        "acceptance_criteria": ["External-send, exfiltration, and memory-write tools declare dlp_redaction."],
    },
    "change_ticket_required": {
        "priority": "P1",
        "title": "Require change tickets for production and repository writes",
        "category": "change_control",
        "evidence_needed": [
            "policy controls that include change_ticket_required",
            "local evidence identifying the change-ticket field or approval workflow",
        ],
        "acceptance_criteria": ["Production, infrastructure, CI/CD, repository, and destructive tools require change tickets."],
    },
    "amount_threshold": {
        "priority": "P1",
        "title": "Add amount thresholds for financial actions",
        "category": "financial_control",
        "evidence_needed": [
            "policy controls that include amount_threshold",
            "local evidence for financial limits and approval breakpoints",
        ],
        "acceptance_criteria": ["Financial tools declare amount_threshold."],
    },
    "scoped_identity": {
        "priority": "P2",
        "title": "Bind tools to scoped least-privilege identities",
        "category": "identity",
        "evidence_needed": [
            "policy controls that include scoped_identity",
            "identity exports or tool_identity_bindings proving which credential each tool uses",
        ],
        "acceptance_criteria": ["Sensitive tools declare scoped_identity and have unambiguous identity binding evidence."],
    },
    "read_only_identity": {
        "priority": "P2",
        "title": "Declare read-only identities for read surfaces",
        "category": "identity",
        "evidence_needed": [
            "policy controls that include read_only_identity",
            "identity exports showing read-only permissions for read tools",
        ],
        "acceptance_criteria": ["Read surfaces use identities without write permissions where practical."],
    },
}


def build_offline_control_analysis(evidence: dict[str, Any]) -> dict[str, Any]:
    """Build static security-control analysis without live calls or runtime claims."""
    tools_by_id = {tool["id"]: tool for tool in all_tools(evidence) if tool.get("id")}
    policies = (evidence.get("approval_policy") or {}).get("policies", [])
    tool_inventory = [_tool_inventory_row(tool) for tool in tools_by_id.values()]
    inventory_by_id = {row["tool"]: row for row in tool_inventory}
    agent_tool_controls: list[dict[str, Any]] = []
    policy_control_gaps: list[dict[str, Any]] = []
    prompt_security_boundaries: list[dict[str, Any]] = []

    for agent in (evidence.get("agents") or {}).get("agents", []):
        prompt_boundary = _prompt_security_boundary(agent, tools_by_id)
        if prompt_boundary:
            prompt_security_boundaries.append(prompt_boundary)
        for tool_id in agent.get("tools", []):
            tool = tools_by_id.get(tool_id)
            if not tool:
                continue
            row = _agent_tool_control_row(agent, tool, policies, inventory_by_id.get(tool_id, {}))
            agent_tool_controls.append(row)
            if row["missing_required_controls"]:
                policy_control_gaps.append(_policy_control_gap(row))

    generic_tools = [row for row in tool_inventory if row["generic_tool"]]
    dangerous_tools = [row for row in tool_inventory if set(row["risk_tags"]).intersection(HIGH_RISK_TAGS)]
    tools_missing_controls = [row for row in agent_tool_controls if row["missing_required_controls"]]
    prompt_boundary_risks = [
        row
        for row in prompt_security_boundaries
        if row["dangerous_tool_count"] and not _agent_has_complete_high_risk_controls(row["agent"], agent_tool_controls)
    ]
    missing_audit = [
        row for row in agent_tool_controls if "audit_logging" in row.get("missing_required_controls", [])
    ]
    total_required_controls = sum(len(row.get("required_controls", [])) for row in agent_tool_controls)
    missing_required_controls_count = sum(
        len(row.get("missing_required_controls", [])) for row in agent_tool_controls
    )
    coverage_percent = (
        round(((total_required_controls - missing_required_controls_count) / total_required_controls) * 100)
        if total_required_controls
        else 100
    )
    roadmap = _offline_remediation_roadmap(generic_tools, agent_tool_controls, prompt_boundary_risks)
    return {
        "summary": {
            "tools": len(tool_inventory),
            "dangerous_tools": len(dangerous_tools),
            "generic_tools": len(generic_tools),
            "agent_tool_controls": len(agent_tool_controls),
            "tools_missing_required_controls": len(tools_missing_controls),
            "policy_control_gaps": len(policy_control_gaps),
            "prompt_security_boundaries": len(prompt_security_boundaries),
            "prompt_boundary_risks": len(prompt_boundary_risks),
            "missing_audit_logging": len(missing_audit),
            "required_control_instances": total_required_controls,
            "missing_control_instances": missing_required_controls_count,
            "control_coverage_percent": coverage_percent,
            "roadmap_items": len(roadmap),
        },
        "tool_inventory": tool_inventory,
        "generic_tools": generic_tools,
        "agent_tool_controls": agent_tool_controls,
        "policy_control_gaps": policy_control_gaps,
        "prompt_security_boundaries": prompt_security_boundaries,
        "prompt_boundary_risks": prompt_boundary_risks,
        "roadmap": roadmap,
    }


def required_controls_for_tool(tool: dict[str, Any]) -> list[str]:
    tags = set(tool.get("risk_tags", []))
    required: set[str] = set()
    if tags.intersection(HIGH_RISK_TAGS):
        required.add("approval_required")
        required.add("audit_logging")
    if "command_execution" in tags:
        required.update({"sandbox_control", "command_allowlist", "secret_denylist"})
    if tags.intersection({"filesystem_read", "filesystem_write", "code_write"}):
        required.update({"sandbox_control", "secret_denylist", "scoped_identity"})
    if tags.intersection({"network_access", "external_message", "data_exfiltration_sink"}):
        required.update({"egress_allowlist"})
    if tags.intersection({"external_message", "data_exfiltration_sink"}):
        required.update({"dlp_redaction"})
    if "secret_access" in tags:
        required.update({"scoped_identity", "secret_denylist"})
    if tags.intersection({"production_write", "infrastructure_write", "ci_cd_write", "repository_write", "destructive_action"}):
        required.update({"change_ticket_required", "scoped_identity"})
    if "financial_action" in tags:
        required.update({"amount_threshold", "scoped_identity"})
    if "memory_write" in tags:
        required.update({"dlp_redaction"})
    if "sensitive_read" in tags and not tags.intersection(HIGH_RISK_TAGS):
        required.update({"scoped_identity", "audit_logging"})
    return sorted(required)


def declared_controls_for_policy(policy_result: dict[str, Any]) -> list[str]:
    controls = set(str(control) for control in policy_result.get("controls", []) if control)
    decision = str(policy_result.get("decision") or "unknown")
    if decision == "approval_required":
        controls.add("approval_required")
    if decision == "deny":
        controls.add("explicit_deny_policy")
        controls.add("approval_required")
    return sorted(controls)


def missing_required_controls(required: list[str], policy_result: dict[str, Any]) -> list[str]:
    declared = set(declared_controls_for_policy(policy_result))
    missing: list[str] = []
    decision = str(policy_result.get("decision") or "unknown")
    for control in required:
        if control == "approval_required" and decision in {"approval_required", "deny"}:
            continue
        if control not in declared:
            missing.append(control)
    return missing


def control_label(control: str) -> str:
    return REQUIRED_CONTROL_LABELS.get(control, control.replace("_", " "))


def _agent_tool_control_row(
    agent: dict[str, Any],
    tool: dict[str, Any],
    policies: list[dict[str, Any]],
    inventory_row: dict[str, Any],
) -> dict[str, Any]:
    policy_result = _policy_result(agent, tool, policies)
    required = required_controls_for_tool(tool)
    declared = declared_controls_for_policy(policy_result)
    missing = missing_required_controls(required, policy_result)
    return {
        "agent": str(agent.get("id", "")),
        "tool": str(tool.get("id", "")),
        "tool_name": str(tool.get("name") or tool.get("id", "")),
        "target_system": str(tool.get("target_system", "unknown")),
        "risk_tags": tool.get("risk_tags", []),
        "risk_source": tool.get("risk_source", "unknown"),
        "risk_confidence": tool.get("risk_confidence", "medium"),
        "source_file": tool.get("source_file", ""),
        "required_controls": required,
        "declared_controls": declared,
        "missing_required_controls": missing,
        "policy_decision": policy_result.get("decision", "unknown"),
        "policy": policy_result.get("policy", ""),
        "policy_rule": policy_result.get("rule", ""),
        "policy_reason": policy_result.get("reason", ""),
        "policy_source_file": policy_result.get("source_file", ""),
        "control_status": "complete" if required and not missing else "missing_controls" if missing else "no_requirements",
        "generic_tool": bool(inventory_row.get("generic_tool")),
        "broad_reasons": inventory_row.get("broad_reasons", []),
        "selector_fields": inventory_row.get("selector_fields", []),
        "selector_constraint_status": inventory_row.get("selector_constraint_status", "none"),
        "constrained_selectors": inventory_row.get("constrained_selectors", []),
        "unconstrained_selectors": inventory_row.get("unconstrained_selectors", []),
        "owner": str(agent.get("owner", "")),
        "environment": str(agent.get("environment", "unknown")),
        "runtime": str(agent.get("runtime", "unknown")),
        "approval_policy": str(agent.get("approval_policy", "")),
    }


def _tool_inventory_row(tool: dict[str, Any]) -> dict[str, Any]:
    schema = tool.get("input_schema") if isinstance(tool.get("input_schema"), dict) else {}
    selector_analysis = _selector_constraint_analysis(schema)
    broad_reasons = _generic_tool_reasons(tool, selector_analysis)
    return {
        "tool": str(tool.get("id", "")),
        "name": str(tool.get("name") or tool.get("id", "")),
        "description": str(tool.get("description", "")),
        "target_system": str(tool.get("target_system", "unknown")),
        "risk_tags": tool.get("risk_tags", []),
        "risk_source": tool.get("risk_source", "unknown"),
        "risk_confidence": tool.get("risk_confidence", "medium"),
        "server_id": str(tool.get("server_id", "")),
        "method": str(tool.get("method", "")),
        "path": str(tool.get("path", "")),
        "security_scopes": tool.get("security_scopes", []),
        "request_data_classes": tool.get("request_data_classes", []),
        "response_data_classes": tool.get("response_data_classes", []),
        "source_file": str(tool.get("source_file", "")),
        "generic_tool": bool(broad_reasons),
        "broad_reasons": broad_reasons,
        "selector_fields": selector_analysis["selector_fields"],
        "selector_constraint_status": selector_analysis["status"],
        "constrained_selectors": selector_analysis["constrained_selectors"],
        "unconstrained_selectors": selector_analysis["unconstrained_selectors"],
        "required_controls": required_controls_for_tool(tool),
    }


def _policy_result(agent: dict[str, Any], tool: dict[str, Any], policies: list[dict[str, Any]]) -> dict[str, Any]:
    risk_tags = tool.get("risk_tags", [])
    return evaluate_policy(
        policies,
        agent.get("approval_policy", ""),
        {
            "agent": agent.get("id"),
            "tool": tool.get("id"),
            "risk_tags": risk_tags,
            "action_class": risk_tags[0] if risk_tags else "",
            "target_system": tool.get("target_system", "unknown"),
            "environment": agent.get("environment", "unknown"),
            "data_classes": (
                tool.get("data_classes", [])
                + tool.get("request_data_classes", [])
                + tool.get("response_data_classes", [])
            ),
            "external_target": "external" if "external_message" in risk_tags else "",
        },
    )


def _policy_control_gap(row: dict[str, Any]) -> dict[str, Any]:
    missing = row.get("missing_required_controls", [])
    return {
        "id": f"offline-control-gap-{_slug(row.get('agent', 'agent'))}-{_slug(row.get('tool', 'tool'))}",
        "type": "offline_tool_control_gap",
        "agent": row.get("agent", ""),
        "tool": row.get("tool", ""),
        "target_system": row.get("target_system", "unknown"),
        "risk_tags": row.get("risk_tags", []),
        "missing_controls": missing,
        "reason": (
            f"{row.get('agent')} uses {row.get('tool')} with {', '.join(row.get('risk_tags', [])) or 'risk'} "
            f"but offline policy evidence is missing {', '.join(control_label(item) for item in missing)}."
        ),
        "requested_evidence": (
            "Add local approval-policy evidence with decision and controls for "
            f"{row.get('tool')}: {', '.join(control_label(item) for item in missing)}."
        ),
        "source_file": row.get("source_file", ""),
        "policy_source_file": row.get("policy_source_file", ""),
    }


def _generic_tool_reasons(tool: dict[str, Any], selector_analysis: dict[str, Any] | None = None) -> list[str]:
    text = " ".join(
        [
            str(tool.get("id", "")),
            str(tool.get("name", "")),
            str(tool.get("description", "")),
            str(tool.get("method", "")),
            str(tool.get("path", "")),
        ]
    )
    reasons = [label for label, pattern in GENERIC_NAME_PATTERNS.items() if pattern.search(text)]
    tags = set(tool.get("risk_tags", []))
    schema = tool.get("input_schema") if isinstance(tool.get("input_schema"), dict) else {}
    selector_analysis = selector_analysis or _selector_constraint_analysis(schema)
    unconstrained_selectors = selector_analysis.get("unconstrained_selectors", [])
    if unconstrained_selectors and tags.intersection(HIGH_RISK_TAGS | {"filesystem_read", "sensitive_read"}):
        reasons.append(f"unconstrained model-controlled selector fields: {', '.join(unconstrained_selectors)}")
    if _schema_is_broad(schema) and tags.intersection(DANGEROUS_TAGS | {"network_access"}):
        reasons.append("broad or unconstrained input schema")
    if tags.intersection({"command_execution", "destructive_action"}) and "generic command execution" not in reasons:
        reasons.append("generic command execution")
    return sorted(set(reasons))


def _selector_fields(schema: dict[str, Any]) -> list[str]:
    return _selector_constraint_analysis(schema).get("unconstrained_selectors", [])


def _selector_constraint_analysis(schema: dict[str, Any]) -> dict[str, Any]:
    records = _selector_constraint_records(schema, ())
    deduped = _dedupe_selector_records(records)
    constrained = sorted(record["path"] for record in deduped if record["status"] == "constrained")
    unconstrained = sorted(record["path"] for record in deduped if record["status"] != "constrained")
    if not deduped:
        status = "none"
    elif constrained and unconstrained:
        status = "partially_constrained"
    elif unconstrained:
        status = "unconstrained"
    else:
        status = "constrained"
    return {
        "status": status,
        "selector_fields": deduped,
        "constrained_selectors": constrained,
        "unconstrained_selectors": unconstrained,
    }


def _selector_constraint_records(
    schema: Any,
    path: tuple[str, ...],
    required_path: bool = True,
    bounded_object_path: bool = True,
) -> list[dict[str, Any]]:
    if not isinstance(schema, dict):
        return []

    records: list[dict[str, Any]] = []
    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    required = schema.get("required") if isinstance(schema.get("required"), list) else []
    required_names = {str(item) for item in required}
    object_bounded = bounded_object_path and schema.get("additionalProperties") is False
    for key, child_schema in properties.items():
        child_path = path + (str(key),)
        child_required = required_path and str(key) in required_names
        if _is_selector_path(child_path):
            records.append(_selector_record(child_path, str(key), child_schema, child_required, object_bounded))
        records.extend(_selector_constraint_records(child_schema, child_path, child_required, object_bounded))

    items = schema.get("items")
    if isinstance(items, dict):
        records.extend(_selector_constraint_records(items, path + ("[]",), required_path, bounded_object_path))

    additional = schema.get("additionalProperties")
    if isinstance(additional, dict):
        records.extend(_selector_constraint_records(additional, path + ("*",), False, False))

    for keyword in ("allOf", "anyOf", "oneOf"):
        variants = schema.get(keyword)
        if isinstance(variants, list):
            for variant in variants:
                records.extend(_selector_constraint_records(variant, path, required_path, bounded_object_path))

    return records


def _selector_record(
    path: tuple[str, ...],
    key: str,
    schema: Any,
    required: bool,
    parent_bounded: bool,
) -> dict[str, Any]:
    child_schema = schema if isinstance(schema, dict) else {}
    constraints = _schema_meaningful_constraint_names(child_schema, required, parent_bounded)
    return {
        "path": _format_schema_path(path),
        "key": key,
        "status": "constrained" if constraints else "unconstrained",
        "constraints": constraints,
        "type": _schema_type_name(child_schema),
    }


def _dedupe_selector_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_path: dict[str, dict[str, Any]] = {}
    for record in records:
        path = str(record.get("path", ""))
        existing = by_path.get(path)
        if not existing:
            by_path[path] = {
                "path": path,
                "key": str(record.get("key", "")),
                "status": str(record.get("status", "unconstrained")),
                "constraints": sorted(str(item) for item in record.get("constraints", [])),
                "type": str(record.get("type", "unknown")),
            }
            continue
        existing["constraints"] = sorted(
            set(existing.get("constraints", [])) | {str(item) for item in record.get("constraints", [])}
        )
        if existing.get("status") != record.get("status"):
            existing["status"] = "partially_constrained"
    return sorted(by_path.values(), key=lambda item: item["path"])


def _is_selector_path(path: tuple[str, ...]) -> bool:
    parts = [_normalize_schema_key(part) for part in path if part not in {"[]", "*"}]
    if not parts:
        return False
    current = parts[-1]
    current_parts = [part for part in current.split("_") if part]
    if current in SCHEMA_SELECTOR_KEYS:
        return True
    if any(part in SCHEMA_SELECTOR_KEYS for part in current_parts):
        return True
    if current == "id" and len(parts) > 1 and parts[-2] in {"customer", "tenant", "ticket"}:
        return True
    if current_parts == ["id"] and len(parts) > 1 and parts[-2] in {"customer", "tenant", "ticket"}:
        return True
    return False


def _normalize_schema_key(value: str) -> str:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value))
    return re.sub(r"[^a-zA-Z0-9]+", "_", separated).lower().strip("_")


def _format_schema_path(path: tuple[str, ...]) -> str:
    formatted = ""
    for part in path:
        if part == "[]":
            formatted += "[]"
        elif part == "*":
            formatted = f"{formatted}.*" if formatted else "*"
        elif formatted:
            formatted += f".{part}"
        else:
            formatted = part
    return formatted


def _schema_constraint_names(schema: dict[str, Any]) -> list[str]:
    return _schema_meaningful_constraint_names(schema, required=True, parent_bounded=True)


def _schema_meaningful_constraint_names(
    schema: dict[str, Any],
    required: bool,
    parent_bounded: bool,
) -> list[str]:
    if not required:
        return []

    constraints: list[str] = []
    if "const" in schema:
        constraints.append("const")
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        constraints.append("enum")

    max_length = schema.get("maxLength")
    if isinstance(schema.get("pattern"), str) and schema.get("pattern") and isinstance(max_length, int) and max_length > 0:
        constraints.extend(["pattern", "maxLength"])

    minimum = any(keyword in schema for keyword in ("minimum", "exclusiveMinimum"))
    maximum = any(keyword in schema for keyword in ("maximum", "exclusiveMaximum"))
    if minimum and maximum:
        constraints.append("numeric_range")

    properties = schema.get("properties")
    if parent_bounded and schema.get("additionalProperties") is False and isinstance(properties, dict):
        constraints.append("bounded_object")
    items = schema.get("items")
    if isinstance(items, dict) and _schema_meaningful_constraint_names(items, required=True, parent_bounded=parent_bounded):
        constraints.append("constrained_items")
    for keyword in ("allOf", "anyOf", "oneOf"):
        variants = schema.get(keyword)
        if isinstance(variants, list) and any(
            isinstance(variant, dict)
            and _schema_meaningful_constraint_names(variant, required=required, parent_bounded=parent_bounded)
            for variant in variants
        ):
            constraints.append(keyword)
    return sorted(set(constraints))


def _schema_type_name(schema: dict[str, Any]) -> str:
    schema_type = schema.get("type")
    if isinstance(schema_type, str):
        return schema_type
    if isinstance(schema_type, list):
        return "|".join(str(item) for item in schema_type)
    if "properties" in schema:
        return "object"
    if "items" in schema:
        return "array"
    return "unknown"


def _schema_is_broad(schema: dict[str, Any]) -> bool:
    if not schema:
        return True
    if schema.get("additionalProperties") is True:
        return True
    properties = schema.get("properties")
    if isinstance(properties, dict) and not properties:
        return True
    return False


def _prompt_security_boundary(agent: dict[str, Any], tools_by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    raw = agent.get("raw") if isinstance(agent.get("raw"), dict) else {}
    fields = _prompt_fields(raw)
    matches: list[str] = []
    for value in fields.values():
        for label, pattern in PROMPT_SECURITY_PATTERNS.items():
            if pattern.search(value):
                matches.append(label)
    dangerous_count = sum(
        1
        for tool_id in agent.get("tools", [])
        if set(tools_by_id.get(tool_id, {}).get("risk_tags", [])).intersection(HIGH_RISK_TAGS)
    )
    if not matches:
        return {}
    return {
        "agent": str(agent.get("id", "")),
        "fields": sorted(fields.keys()),
        "matched_terms": sorted(set(matches)),
        "dangerous_tool_count": dangerous_count,
        "approval_policy": str(agent.get("approval_policy", "")),
        "source_file": str(agent.get("source_file", "")),
        "reason": "Agent evidence contains prompt-language security instructions; offline policy controls should carry the boundary.",
    }


def _prompt_fields(raw: dict[str, Any]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key, value in raw.items():
        normalized = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
        if normalized in PROMPT_FIELD_HINTS or "prompt" in normalized or "instruction" in normalized or "guardrail" in normalized:
            text = _stringify_prompt_value(value)
            if text:
                fields[str(key)] = text
    return fields


def _stringify_prompt_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(_stringify_prompt_value(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return ""


def _agent_has_complete_high_risk_controls(agent_id: str, rows: list[dict[str, Any]]) -> bool:
    agent_rows = [row for row in rows if row.get("agent") == agent_id and row.get("required_controls")]
    return bool(agent_rows) and all(not row.get("missing_required_controls") for row in agent_rows)


def _offline_remediation_roadmap(
    generic_tools: list[dict[str, Any]],
    agent_tool_controls: list[dict[str, Any]],
    prompt_boundary_risks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    generic_tool_ids = _unique(row.get("tool", "") for row in generic_tools)
    if generic_tool_ids:
        generic_rows = [
            row for row in agent_tool_controls if row.get("generic_tool") or row.get("tool") in generic_tool_ids
        ]
        broad_reasons = _unique(
            reason for row in generic_tools for reason in row.get("broad_reasons", [])
        )
        items.append(
            {
                "id": "roadmap-narrow-generic-tools",
                "priority": "P1",
                "category": "tool_surface",
                "title": "Replace or constrain generic tool surfaces",
                "reason": (
                    f"{len(generic_tool_ids)} tools look like broad command, filesystem, network, or query surfaces: "
                    f"{', '.join(broad_reasons) or 'broad tool surface'}."
                ),
                "affected_agents": _unique(row.get("agent", "") for row in generic_rows),
                "affected_tools": generic_tool_ids,
                "affected_count": len(generic_rows) or len(generic_tool_ids),
                "controls": ["narrow_typed_tools", "resource_constraints", "scoped_identity"],
                "evidence_needed": [
                    "replace broad tools with narrow typed tool descriptors",
                    "add input schema constraints for commands, paths, URLs, queries, and resource identifiers",
                    "bind each remaining broad tool to a scoped identity and explicit approval policy",
                ],
                "acceptance_criteria": [
                    "No high-risk tool is generic unless it has explicit schema/resource constraints and policy controls.",
                ],
                "source": "offline_static",
            }
        )

    rows_by_control: dict[str, list[dict[str, Any]]] = {}
    for row in agent_tool_controls:
        for control in row.get("missing_required_controls", []):
            rows_by_control.setdefault(control, []).append(row)
    for control, rows in rows_by_control.items():
        guidance = CONTROL_ROADMAP_GUIDANCE.get(
            control,
            {
                "priority": "P2",
                "title": f"Add {control_label(control)} evidence",
                "category": "policy",
                "evidence_needed": [f"policy controls that include {control}"],
                "acceptance_criteria": [f"Affected tools declare {control}."],
            },
        )
        items.append(
            {
                "id": f"roadmap-control-{_slug(control)}",
                "priority": guidance["priority"],
                "category": guidance["category"],
                "title": guidance["title"],
                "reason": (
                    f"{len(rows)} agent-tool relationships are missing {control_label(control)} evidence."
                ),
                "affected_agents": _unique(row.get("agent", "") for row in rows),
                "affected_tools": _unique(row.get("tool", "") for row in rows),
                "affected_count": len(rows),
                "controls": [control],
                "evidence_needed": list(guidance["evidence_needed"]),
                "acceptance_criteria": list(guidance["acceptance_criteria"]),
                "source": "offline_policy",
            }
        )

    if prompt_boundary_risks:
        items.append(
            {
                "id": "roadmap-move-prompt-security-boundaries",
                "priority": "P1",
                "category": "prompt_boundary",
                "title": "Move security decisions out of prompt text",
                "reason": (
                    f"{len(prompt_boundary_risks)} agents use prompt-language security instructions "
                    "while high-risk tool controls are incomplete."
                ),
                "affected_agents": _unique(row.get("agent", "") for row in prompt_boundary_risks),
                "affected_tools": [],
                "affected_count": len(prompt_boundary_risks),
                "controls": ["approval_required", "scoped_identity", "sandbox_control", "egress_allowlist", "audit_logging"],
                "evidence_needed": [
                    "approval-policy.json rules for high-risk tools used by the affected agents",
                    "identity, sandbox, egress, DLP, and audit controls in local evidence",
                ],
                "acceptance_criteria": [
                    "Prompt instructions remain advisory and findings are cleared by policy/control evidence.",
                ],
                "source": "offline_static",
            }
        )

    priority_order = {"P1": 0, "P2": 1, "P3": 2}
    return sorted(items, key=lambda item: (priority_order.get(str(item.get("priority", "P3")), 9), item["id"]))


def _unique(values: Any) -> list[str]:
    return sorted({str(value) for value in values if value})


def _slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value)).strip("-")
    return slug or "unknown"
