"""Input validation and evidence loading."""

from __future__ import annotations

from datetime import date
from dataclasses import dataclass, field
from typing import Any

from ..adapters.agents import parse_agents
from ..adapters.approval_policy import parse_approval_policy
from ..adapters.data_catalog import parse_data_catalog
from ..adapters.events import parse_events
from ..adapters.identity import parse_identity
from ..adapters.mcp import parse_mcp
from ..adapters.openapi import parse_openapi
from ..schemas import (
    AUTONOMY_VALUES,
    CONFIDENCE_VALUES,
    CONTROL_TAGS,
    DECISION_VALUES,
    DANGEROUS_TAGS,
    ENVIRONMENT_VALUES,
    RISK_TAGS,
    SENSITIVITY_VALUES,
    SENSITIVE_DATA_CLASSES,
)

EVENT_TYPES = {
    "agent.session_started",
    "agent.tool_call",
    "agent.tool_result",
    "agent.approval_requested",
    "agent.approval_granted",
    "agent.approval_denied",
    "agent.policy_denied",
    "agent.memory_read",
    "agent.memory_write",
    "agent.external_send",
    "agent.delegation",
    "agent.error",
}
TRUST_VALUES = {"trusted", "untrusted", "mixed", "unknown"}
EVENT_DECISION_VALUES = DECISION_VALUES | {"denied"}
MCP_TRANSPORT_VALUES = {"stdio", "http", "sse", "websocket", "remote_mcp", "copilot_plugin", "copilot_builtin", "framework_static", "local_config", "local_manifest", "unknown"}
RISK_ACCEPTANCE_STATUS_VALUES = {"accepted", "revoked"}
RISK_ACCEPTANCE_SCOPE_FIELDS = {"finding_id", "path_id", "rule_id", "agent", "owner", "environment", "business_unit"}
SUPPORTED_SCHEMA_VERSION = "0.1"


@dataclass
class ValidationResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    info: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "errors": self.errors, "warnings": self.warnings, "info": self.info}


def load_evidence(
    *,
    agents: str | None = None,
    mcp: str | None = None,
    identity: str | None = None,
    data_catalog: str | None = None,
    approval_policy: str | None = None,
    events: str | None = None,
    openapi: str | None = None,
) -> dict[str, Any]:
    mcp_evidence = parse_mcp(mcp)
    openapi_evidence = parse_openapi(openapi)
    return {
        "agents": parse_agents(agents),
        "mcp": mcp_evidence,
        "openapi": openapi_evidence,
        "identity": parse_identity(identity),
        "data_catalog": parse_data_catalog(data_catalog),
        "approval_policy": parse_approval_policy(approval_policy),
        "events": parse_events(events),
    }


def all_tools(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    tools: list[dict[str, Any]] = []
    for section_name in ["mcp", "openapi"]:
        section = evidence.get(section_name, {})
        if not isinstance(section, dict):
            continue
        raw_tools = section.get("tools", [])
        if not isinstance(raw_tools, list):
            continue
        tools.extend(tool for tool in raw_tools if isinstance(tool, dict))
    return tools


def source_files(evidence: dict[str, Any]) -> list[str]:
    files = []
    for item in evidence.values():
        source_file = item.get("source_file") if isinstance(item, dict) else None
        if source_file:
            files.append(source_file)
    return sorted(set(files))


def _duplicate_ids(items: list[dict[str, Any]], label: str) -> list[str]:
    seen: set[str] = set()
    duplicates: list[str] = []
    for item in items:
        item_id = item.get("id", "")
        if not item_id:
            continue
        if item_id in seen:
            duplicates.append(f"duplicate {label} id: {item_id}")
        seen.add(item_id)
    return duplicates


def _raw_missing(item: dict[str, Any], field: str) -> bool:
    raw = item.get("raw", item)
    return not isinstance(raw, dict) or field not in raw


def _section_payload(evidence: dict[str, Any], section: str, label: str, result: ValidationResult) -> dict[str, Any]:
    payload = evidence.get(section, {})
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        result.errors.append(f"{label} must be an object")
        return {}
    return payload


def _list_field(payload: dict[str, Any], field: str, label: str, result: ValidationResult) -> list[Any]:
    value = payload.get(field, [])
    if value is None:
        return []
    if not isinstance(value, list):
        result.errors.append(f"{label} must be a list")
        return []
    return value


def _dict_items(items: list[Any], label: str, result: ValidationResult) -> list[dict[str, Any]]:
    dicts = []
    for index, item in enumerate(items):
        if isinstance(item, dict):
            dicts.append(item)
        else:
            result.errors.append(f"{label}[{index}] must be an object")
    return dicts


def _raw_value(item: dict[str, Any], field: str, default: Any = None) -> Any:
    raw = item.get("raw", item)
    if isinstance(raw, dict):
        return raw.get(field, default)
    return default


def _is_list_value(item: dict[str, Any], field: str) -> bool:
    raw = item.get("raw", item)
    return isinstance(raw, dict) and (field not in raw or isinstance(raw.get(field), list))


def _schema_version_warning(label: str, payload: dict[str, Any]) -> str:
    version = str(payload.get("schema_version", SUPPORTED_SCHEMA_VERSION))
    if version == SUPPORTED_SCHEMA_VERSION:
        return ""
    try:
        numeric_version = tuple(int(part) for part in version.split("."))
        supported_version = tuple(int(part) for part in SUPPORTED_SCHEMA_VERSION.split("."))
    except ValueError:
        return f"{label} has unsupported schema_version: {version}"
    if numeric_version > supported_version:
        return f"{label} schema_version {version} is newer than supported {SUPPORTED_SCHEMA_VERSION}; validation used compatibility mode"
    return f"{label} schema_version {version} is older than supported {SUPPORTED_SCHEMA_VERSION}; validation used compatibility mode"


def _valid_iso_date(value: str) -> bool:
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def validate_evidence(evidence: dict[str, Any]) -> ValidationResult:
    result = ValidationResult(evidence=evidence)
    agents_payload = _section_payload(evidence, "agents", "agentguard.json", result)
    mcp_payload = _section_payload(evidence, "mcp", "mcp-servers.json", result)
    openapi_payload = _section_payload(evidence, "openapi", "openapi evidence", result)
    identity_payload = _section_payload(evidence, "identity", "identity.json", result)
    data_payload = _section_payload(evidence, "data_catalog", "data-catalog.json", result)
    policy_payload = _section_payload(evidence, "approval_policy", "approval-policy.json", result)
    events_payload = _section_payload(evidence, "events", "events.jsonl", result)

    agents = _dict_items(_list_field(agents_payload, "agents", "agentguard.json agents", result), "agentguard.json agents", result)
    input_sources = _dict_items(
        _list_field(agents_payload, "input_sources", "agentguard.json input_sources", result),
        "agentguard.json input_sources",
        result,
    )
    memory_stores = _dict_items(
        _list_field(agents_payload, "memory_stores", "agentguard.json memory_stores", result),
        "agentguard.json memory_stores",
        result,
    )
    risk_acceptances = _dict_items(
        _list_field(agents_payload, "risk_acceptances", "agentguard.json risk_acceptances", result),
        "agentguard.json risk_acceptances",
        result,
    )
    mcp_servers = _dict_items(
        _list_field(mcp_payload, "servers", "mcp-servers.json servers", result),
        "mcp-servers.json servers",
        result,
    )
    tools = _dict_items(_list_field(mcp_payload, "tools", "mcp-servers.json tools", result), "mcp-servers.json tools", result)
    tools.extend(
        _dict_items(_list_field(openapi_payload, "tools", "openapi tools", result), "openapi tools", result)
    )
    identities = _dict_items(
        _list_field(identity_payload, "identities", "identity.json identities", result),
        "identity.json identities",
        result,
    )
    policies = _dict_items(
        _list_field(policy_payload, "policies", "approval-policy.json policies", result),
        "approval-policy.json policies",
        result,
    )
    policy_evaluations = _dict_items(
        _list_field(policy_payload, "policy_evaluations", "approval-policy.json policy_evaluations", result),
        "approval-policy.json policy_evaluations",
        result,
    )
    events = _dict_items(_list_field(events_payload, "events", "events.jsonl events", result), "events.jsonl events", result)
    data_sources = _dict_items(
        _list_field(data_payload, "data_sources", "data-catalog.json data_sources", result),
        "data-catalog.json data_sources",
        result,
    )

    for label, payload in [
        ("agentguard.json", evidence.get("agents", {})),
        ("mcp-servers.json", evidence.get("mcp", {})),
        ("identity.json", evidence.get("identity", {})),
        ("data-catalog.json", evidence.get("data_catalog", {})),
        ("approval-policy.json", evidence.get("approval_policy", {})),
    ]:
        if not isinstance(payload, dict):
            continue
        warning = _schema_version_warning(label, payload)
        if warning:
            result.warnings.append(warning)

    result.errors.extend(_duplicate_ids(agents, "agent"))
    result.errors.extend(_duplicate_ids(risk_acceptances, "risk_acceptance"))
    result.errors.extend(_duplicate_ids(input_sources, "input_source"))
    result.errors.extend(_duplicate_ids(memory_stores, "memory_store"))
    result.errors.extend(_duplicate_ids(mcp_servers, "mcp_server"))
    result.errors.extend(_duplicate_ids(tools, "tool"))
    result.errors.extend(_duplicate_ids(identities, "identity"))
    result.errors.extend(_duplicate_ids(data_sources, "data_source"))
    result.errors.extend(_duplicate_ids(policies, "approval_policy"))
    result.errors.extend(_duplicate_ids(policy_evaluations, "policy_evaluation"))
    result.errors.extend(_duplicate_ids(events, "event"))

    tool_ids = {tool.get("id") for tool in tools if tool.get("id")}
    tools_by_id = {tool.get("id"): tool for tool in tools if tool.get("id")}
    server_ids = {server.get("id") for server in mcp_servers if server.get("id")}
    identity_ids = {identity.get("id") for identity in identities if identity.get("id")}
    identities_by_id = {identity.get("id"): identity for identity in identities if identity.get("id")}
    agent_ids = {agent.get("id") for agent in agents if agent.get("id")}
    input_ids = {item.get("id") for item in input_sources if item.get("id")}
    memory_ids = {item.get("id") for item in memory_stores if item.get("id")}

    for acceptance in risk_acceptances:
        acceptance_id = str(acceptance.get("id") or "<unknown>")
        if not acceptance.get("id"):
            result.errors.append("risk acceptance missing required field: id")
        status = str(acceptance.get("status") or "accepted")
        if status not in RISK_ACCEPTANCE_STATUS_VALUES:
            result.errors.append(f"risk acceptance {acceptance_id} has invalid status: {status}")
        scope = acceptance.get("scope")
        if not isinstance(scope, dict):
            result.errors.append(f"risk acceptance {acceptance_id} field must be an object: scope")
            scope = {}
        if not any(scope.get(field) for field in RISK_ACCEPTANCE_SCOPE_FIELDS):
            result.errors.append(
                f"risk acceptance {acceptance_id} must scope to at least one of: "
                f"{', '.join(sorted(RISK_ACCEPTANCE_SCOPE_FIELDS))}"
            )
        if scope.get("agent") and scope["agent"] not in agent_ids:
            result.warnings.append(f"risk acceptance {acceptance_id} references unknown agent: {scope['agent']}")
        if scope.get("environment") and scope["environment"] not in ENVIRONMENT_VALUES:
            result.warnings.append(f"risk acceptance {acceptance_id} has invalid environment scope: {scope['environment']}")
        expires_at = str(acceptance.get("expires_at") or "")
        if status == "accepted" and not expires_at:
            result.warnings.append(f"risk acceptance {acceptance_id} is missing expires_at")
        if expires_at and not _valid_iso_date(expires_at):
            result.errors.append(f"risk acceptance {acceptance_id} has invalid expires_at: {expires_at}; expected YYYY-MM-DD")
        if status == "accepted" and not acceptance.get("reason"):
            result.warnings.append(f"risk acceptance {acceptance_id} is missing reason")

    if not agents:
        result.info.append("no agent evidence provided; add agentguard.json with at least one agent before scanning")
    if not tools:
        result.info.append("no MCP or OpenAPI tool evidence provided")
    if not identities:
        result.info.append("no identity evidence provided; identity and permission visibility gaps may be emitted")
    if not data_sources:
        result.info.append("no data catalog evidence provided; sensitive data reachability may be underreported")
    if not policies:
        result.info.append("no approval policy evidence provided")
    if not events:
        result.info.append("no runtime event evidence provided; findings will be based on static evidence only")
    for payload, prefix, label in [
        (agents_payload, "agentguard", "agentguard.json warnings"),
        (mcp_payload, "mcp", "mcp-servers.json warnings"),
        (openapi_payload, "openapi", "openapi warnings"),
        (identity_payload, "identity", "identity.json warnings"),
        (data_payload, "data_catalog", "data-catalog.json warnings"),
        (policy_payload, "approval_policy", "approval-policy.json warnings"),
        (events_payload, "events", "events.jsonl warnings"),
    ]:
        for warning in _list_field(payload, "warnings", label, result):
            result.warnings.append(f"{prefix}: {warning}")

    for agent in agents:
        agent_id = agent.get("id", "")
        raw_agent_id = _raw_value(agent, "id", "")
        if not raw_agent_id:
            result.errors.append("agent missing required field: id")
        for required_field in ["tools", "identities", "input_sources", "autonomy"]:
            if _raw_missing(agent, required_field):
                result.errors.append(f"agent {agent_id or '<unknown>'} missing required field: {required_field}")
        for list_field in ["tools", "identities", "input_sources", "memory"]:
            if not _is_list_value(agent, list_field):
                result.errors.append(f"agent {agent_id or '<unknown>'} field must be a list: {list_field}")
        raw_bindings = _raw_value(agent, "tool_identity_bindings", [])
        if raw_bindings and not isinstance(raw_bindings, (list, dict)):
            result.errors.append(f"agent {agent_id or '<unknown>'} field must be a list or object: tool_identity_bindings")
        raw_autonomy = _raw_value(agent, "autonomy", "unknown")
        if raw_autonomy not in AUTONOMY_VALUES:
            result.errors.append(f"agent {agent_id or '<unknown>'} has invalid autonomy: {raw_autonomy}")
        raw_environment = _raw_value(agent, "environment", "unknown")
        if raw_environment not in ENVIRONMENT_VALUES:
            result.warnings.append(f"agent {agent_id or '<unknown>'} has invalid environment: {raw_environment}")
        for tool in agent.get("tools", []):
            if tool not in tool_ids:
                result.warnings.append(f"agent {agent_id} references unknown tool: {tool}")
        for identity in agent.get("identities", []):
            if identity not in identity_ids:
                result.warnings.append(f"agent {agent_id} references unknown identity: {identity}")
        for input_source in agent.get("input_sources", []):
            if input_source not in input_ids:
                result.warnings.append(f"agent {agent_id} references unknown input source: {input_source}")
        for memory in agent.get("memory", []):
            if memory not in memory_ids:
                result.warnings.append(f"agent {agent_id} references unknown memory store: {memory}")
        bindings = _dict_items(
            _list_field(agent, "tool_identity_bindings", f"agent {agent_id or '<unknown>'} tool_identity_bindings", result),
            f"agent {agent_id or '<unknown>'} tool_identity_bindings",
            result,
        )
        for binding in bindings:
            tool_id = str(binding.get("tool") or "")
            identity_id = str(binding.get("identity") or "")
            if not tool_id:
                result.errors.append(f"agent {agent_id or '<unknown>'} tool_identity_binding missing required field: tool")
            if not identity_id:
                result.errors.append(f"agent {agent_id or '<unknown>'} tool_identity_binding missing required field: identity")
            if not tool_id or not identity_id:
                continue
            if tool_id not in agent.get("tools", []):
                result.warnings.append(f"agent {agent_id} binds identity to tool not listed by agent: {tool_id}")
            if identity_id not in agent.get("identities", []):
                result.warnings.append(f"agent {agent_id} binds tool to identity not listed by agent: {identity_id}")
            if tool_id not in tool_ids:
                result.warnings.append(f"agent {agent_id} binds identity to unknown tool: {tool_id}")
            if identity_id not in identity_ids:
                result.warnings.append(f"agent {agent_id} binds tool to unknown identity: {identity_id}")
            tool = tools_by_id.get(tool_id)
            identity = identities_by_id.get(identity_id)
            tool_target = tool.get("target_system") if tool else ""
            identity_target = identity.get("target_system") if identity else ""
            if tool_target and identity_target and tool_target != "unknown" and identity_target != tool_target:
                result.warnings.append(
                    f"agent {agent_id} binds tool {tool_id} target_system {tool_target} "
                    f"to identity {identity_id} target_system {identity_target}"
                )

    for input_source in input_sources:
        if not _raw_value(input_source, "id", ""):
            result.errors.append("input source missing required field: id")
        trust = _raw_value(input_source, "trust", "unknown")
        if trust not in TRUST_VALUES:
            result.warnings.append(f"input source {input_source.get('id', '<unknown>')} has invalid trust value: {trust}")

    for identity in identities:
        if not _raw_value(identity, "id", ""):
            result.errors.append("identity missing required field: id")
        if not _raw_value(identity, "type", ""):
            result.errors.append(f"identity {identity.get('id', '<unknown>')} missing required field: type")
        if not _raw_value(identity, "target_system", ""):
            result.errors.append(f"identity {identity.get('id', '<unknown>')} missing required field: target_system")
        if not _is_list_value(identity, "scopes"):
            result.errors.append(f"identity {identity.get('id', '<unknown>')} field must be a list: scopes")
        if identity.get("target_system") and not identity.get("permissions"):
            result.warnings.append(f"identity {identity.get('id')} has target system but no permissions")
        permissions = _dict_items(
            _list_field(identity, "permissions", f"identity {identity.get('id', '<unknown>')} permissions", result),
            f"identity {identity.get('id', '<unknown>')} permissions",
            result,
        )
        for permission in permissions:
            confidence = permission.get("confidence", "medium")
            if confidence not in CONFIDENCE_VALUES:
                result.warnings.append(
                    f"identity {identity.get('id')} permission {permission.get('resource')} has invalid confidence: {confidence}"
                )

    for data_source in data_sources:
        if not _raw_value(data_source, "id", ""):
            result.errors.append("data source missing required field: id")
        raw_sensitivity = _raw_value(data_source, "sensitivity", "unknown")
        if raw_sensitivity not in SENSITIVITY_VALUES:
            result.warnings.append(f"data source {data_source.get('id', '<unknown>')} has invalid sensitivity: {raw_sensitivity}")
        if not _is_list_value(data_source, "data_classes"):
            result.errors.append(f"data source {data_source.get('id', '<unknown>')} field must be a list: data_classes")

    for server in mcp_servers:
        if not _raw_value(server, "id", ""):
            result.errors.append("mcp server missing required field: id")
        if not _is_list_value(server, "tools"):
            result.errors.append(f"mcp server {server.get('id', '<unknown>')} field must be a list: tools")
        transport = str(server.get("transport", "unknown"))
        if transport not in MCP_TRANSPORT_VALUES:
            result.warnings.append(f"mcp server {server.get('id', '<unknown>')} has uncommon transport: {transport}")

    for tool in tools:
        if not tool.get("id") and not tool.get("name"):
            result.errors.append("tool missing required field: id/name")
        if tool.get("server_id") and tool.get("server_id") not in server_ids:
            result.warnings.append(f"tool {tool.get('id', '<unknown>')} references unknown MCP server: {tool.get('server_id')}")
        input_schema = _raw_value(tool, "input_schema", {})
        if input_schema and not isinstance(input_schema, dict):
            result.errors.append(f"tool {tool.get('id', '<unknown>')} field must be an object: input_schema")
        risk_confidence = tool.get("risk_confidence", "medium")
        if risk_confidence not in CONFIDENCE_VALUES:
            result.warnings.append(f"tool {tool.get('id', '<unknown>')} has invalid risk confidence: {risk_confidence}")
        raw_tags = _raw_value(tool, "risk_tags", [])
        if raw_tags and not isinstance(raw_tags, list):
            result.errors.append(f"tool {tool.get('id', '<unknown>')} field must be a list: risk_tags")
        for tag in raw_tags if isinstance(raw_tags, list) else []:
            if tag not in RISK_TAGS:
                result.warnings.append(f"tool {tool.get('id', '<unknown>')} has unknown risk tag: {tag}")

    sensitive_or_dangerous = [
        tool
        for tool in tools
        if set(tool.get("risk_tags", [])).intersection(DANGEROUS_TAGS | {"financial_action", "external_message", "sensitive_read"})
    ]
    for tool in sensitive_or_dangerous:
        if not policies:
            result.warnings.append(f"sensitive tool has no approval policy evidence: {tool.get('id')}")
        if "sensitive_read" in tool.get("risk_tags", []) and tool.get("target_system") == "unknown":
            result.warnings.append(f"sensitive-looking tool has unknown data classification: {tool.get('id')}")

    for memory in memory_stores:
        if not _is_list_value(memory, "data_classes"):
            result.errors.append(f"memory store {memory.get('id', '<unknown>')} field must be a list: data_classes")
        if not _is_list_value(memory, "source_evidence"):
            result.errors.append(f"memory store {memory.get('id', '<unknown>')} field must be a list: source_evidence")
        sensitive = set(memory.get("data_classes", [])).intersection(SENSITIVE_DATA_CLASSES)
        if memory.get("persistence") == "persistent" and sensitive and memory.get("retention_policy") in {"", "unknown"}:
            result.warnings.append(f"persistent memory has no retention policy: {memory.get('id')}")

    for policy in policies:
        if not _raw_value(policy, "id", ""):
            result.errors.append("approval policy missing required field: id")
        rules = _dict_items(
            _list_field(policy, "rules", f"approval policy {policy.get('id', '<unknown>')} rules", result),
            f"approval policy {policy.get('id', '<unknown>')} rules",
            result,
        )
        for rule in rules:
            if not _raw_value(rule, "id", ""):
                result.errors.append(f"approval policy {policy.get('id', '<unknown>')} has rule missing required field: id")
            decision = _raw_value(rule, "decision", "unknown")
            if decision not in DECISION_VALUES:
                result.errors.append(f"approval policy {policy.get('id', '<unknown>')} rule {rule.get('id')} has invalid decision: {decision}")
            match = rule.get("match", {})
            if "agent" in match and match["agent"] not in agent_ids:
                result.warnings.append(f"policy {policy.get('id')} references unknown agent: {match['agent']}")
            if "tool" in match and match["tool"] not in tool_ids:
                result.warnings.append(f"policy {policy.get('id')} references unknown tool: {match['tool']}")
            if "risk_tag" in match:
                tags = match["risk_tag"] if isinstance(match["risk_tag"], list) else [match["risk_tag"]]
                for tag in tags:
                    if tag not in RISK_TAGS:
                        result.warnings.append(f"policy {policy.get('id')} references unknown risk tag: {tag}")
            raw_controls = _raw_value(rule, "controls", [])
            controls = rule.get("controls", [])
            if raw_controls and not isinstance(raw_controls, list):
                result.errors.append(f"approval policy {policy.get('id', '<unknown>')} rule {rule.get('id')} field must be a list: controls")
            for control in controls if isinstance(controls, list) else []:
                if control not in CONTROL_TAGS:
                    result.warnings.append(f"policy {policy.get('id')} references unknown control: {control}")

    for evaluation in policy_evaluations:
        evaluation_id = str(evaluation.get("id") or "<unknown>")
        if not evaluation.get("id"):
            result.errors.append("policy evaluation missing required field: id")
        engine = str(evaluation.get("engine") or "")
        if engine and engine not in {"opa_rego", "cedar"}:
            result.warnings.append(f"policy evaluation {evaluation_id} has unknown engine: {engine}")
        decision = str(evaluation.get("decision") or "unknown")
        if decision not in DECISION_VALUES:
            result.errors.append(f"policy evaluation {evaluation_id} has invalid decision: {decision}")
        if not isinstance(evaluation.get("match", {}), dict):
            result.errors.append(f"policy evaluation {evaluation_id} field must be an object: match")
        controls = evaluation.get("controls", [])
        if controls and not isinstance(controls, list):
            result.errors.append(f"policy evaluation {evaluation_id} field must be a list: controls")
            controls = []
        for control in controls if isinstance(controls, list) else []:
            if control not in CONTROL_TAGS:
                result.warnings.append(f"policy evaluation {evaluation_id} references unknown control: {control}")

    for event in events:
        if event.get("event_type") not in EVENT_TYPES:
            result.warnings.append(f"event {event.get('id')} has unknown event_type: {event.get('event_type')}")
        if event.get("confidence") not in CONFIDENCE_VALUES:
            result.warnings.append(f"event {event.get('id')} has invalid confidence: {event.get('confidence')}")
        if event.get("decision") and event.get("decision") not in EVENT_DECISION_VALUES:
            result.warnings.append(f"event {event.get('id')} has invalid decision: {event.get('decision')}")
        if event.get("input_trust") and event.get("input_trust") not in TRUST_VALUES:
            result.warnings.append(f"event {event.get('id')} has invalid input_trust: {event.get('input_trust')}")
        if not _is_list_value(event, "data_classes"):
            result.errors.append(f"event {event.get('id', '<unknown>')} field must be a list: data_classes")
        if event.get("event_type") in {"agent.tool_call", "agent.tool_result", "agent.approval_requested", "agent.approval_granted", "agent.approval_denied", "agent.policy_denied"}:
            if not event.get("session_id"):
                result.warnings.append(f"event {event.get('id')} is missing session_id")
            if not event.get("timestamp"):
                result.warnings.append(f"event {event.get('id')} is missing timestamp")
        if event.get("agent") and event.get("agent") not in agent_ids:
            result.warnings.append(f"event {event.get('id')} references unknown agent: {event.get('agent')}")
        if event.get("tool") and event.get("tool") not in tool_ids:
            result.warnings.append(f"event {event.get('id')} references unknown tool: {event.get('tool')}")

    return result
