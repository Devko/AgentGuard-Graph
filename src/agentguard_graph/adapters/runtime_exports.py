"""Import common runtime JSON exports into AgentGuard event records."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..errors import EvidenceLoadError
from ..schemas import source_name, string_list


READ_WORDS = {"get", "list", "read", "search", "describe", "lookup", "view", "select"}
WRITE_WORDS = {"create", "update", "write", "delete", "remove", "send", "post", "apply", "deploy", "merge", "approve"}
DENY_VALUES = {"deny", "denied", "blocked", "rejected", "failure", "failed", "error", "unauthorized", "forbidden"}
ALLOW_VALUES = {"allow", "allowed", "approved", "granted", "success", "succeeded", "completed", "pass", "passed"}


def parse_agent_trace_export(path: str | Path) -> dict[str, Any]:
    data, source = _load_runtime_json(path)
    records = _records(data, ["events", "spans", "traces", "runs", "items", "records"])
    return _result("agent_trace", source, [_event_from_trace(item, source, index) for index, item in enumerate(records, start=1)])


def parse_approval_broker_export(path: str | Path) -> dict[str, Any]:
    data, source = _load_runtime_json(path)
    records = _records(data, ["approvals", "approval_requests", "requests", "decisions", "events", "items", "records"])
    return _result("approval_broker", source, [_event_from_approval(item, source, index) for index, item in enumerate(records, start=1)])


def parse_mcp_host_log(path: str | Path) -> dict[str, Any]:
    data, source = _load_runtime_json(path)
    records = _records(data, ["tool_calls", "calls", "events", "requests", "items", "records"])
    return _result("mcp_host", source, [_event_from_mcp(item, source, index) for index, item in enumerate(records, start=1)])


def parse_ci_system_log(path: str | Path) -> dict[str, Any]:
    data, source = _load_runtime_json(path)
    records = _records(data, ["workflow_runs", "jobs", "steps", "events", "runs", "items", "records"])
    return _result("ci_system", source, [_event_from_ci(item, source, index) for index, item in enumerate(records, start=1)])


def parse_cloud_audit_log(path: str | Path) -> dict[str, Any]:
    data, source = _load_runtime_json(path)
    records = _records(data, ["Records", "protoPayloads", "value", "events", "items", "records", "logs"])
    return _result("cloud_audit", source, [_event_from_cloud(item, source, index) for index, item in enumerate(records, start=1)])


def _load_runtime_json(path: str | Path) -> tuple[Any, str]:
    runtime_path = Path(path)
    if not runtime_path.exists():
        raise EvidenceLoadError(f"{runtime_path}: runtime export file not found")
    try:
        data = json.loads(runtime_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EvidenceLoadError(f"{runtime_path}:{exc.lineno}:{exc.colno}: invalid JSON: {exc.msg}") from exc
    except UnicodeDecodeError as exc:
        raise EvidenceLoadError(f"{runtime_path}: cannot decode as UTF-8: {exc.reason}") from exc
    except OSError as exc:
        raise EvidenceLoadError(f"{runtime_path}: cannot read file: {exc}") from exc
    if not isinstance(data, (dict, list)):
        raise EvidenceLoadError(f"{runtime_path}: runtime export must be a JSON object or array")
    return data, source_name(runtime_path)


def _result(kind: str, source: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    clean_events = [event for event in events if event]
    warnings = []
    if not clean_events:
        warnings.append(f"{source}: no runtime events were extracted from {kind} export")
    return {"kind": kind, "source_file": source, "events": clean_events, "warnings": warnings}


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


def _event_from_trace(item: dict[str, Any], source: str, index: int) -> dict[str, Any]:
    attributes = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
    resource = item.get("resource") if isinstance(item.get("resource"), dict) else {}
    tool = _first(item, "tool", "tool_name", "function", "function_name", "name", "operation", "operation_name") or _first(
        attributes, "tool.name", "gen_ai.tool.name", "function.name", "operation.name"
    )
    raw_type = _first(item, "event_type", "type", "span_type", "kind")
    event_type = "agent.tool_call" if tool or "tool" in raw_type.lower() else "agent.session_started"
    return _event(
        source_kind="agent_trace",
        source=source,
        index=index,
        raw=item,
        event_type=event_type,
        timestamp=_timestamp(item),
        agent=_first(item, "agent", "agent_id", "agent_name", "runtime", "service_name")
        or _first(attributes, "agent", "agent.id", "agent.name", "service.name")
        or _first(resource, "service.name", "service_name"),
        session_id=_first(item, "session_id", "session", "trace_id", "traceId", "run_id", "conversation_id", "thread_id")
        or _first(attributes, "session_id", "session.id", "trace_id", "run_id", "conversation.id", "thread.id"),
        tool=tool,
        action_class=_first(item, "action_class", "risk_tag", "operation_type") or _first(attributes, "action_class", "risk.tag"),
        data_classes=string_list(item.get("data_classes") or item.get("dataClassifications") or attributes.get("data_classes")),
        identity=_first(item, "identity", "principal", "user", "actor") or _first(attributes, "identity", "principal", "user.id"),
        target=_first(item, "target", "target_system", "resource") or _first(attributes, "target", "target.system", "resource.name"),
        decision=_decision(item),
        policy=_first(item, "policy", "policy_id", "guardrail", "rule") or _first(attributes, "policy", "policy.id", "guardrail"),
        confidence=str(item.get("confidence") or "medium"),
    )


def _event_from_approval(item: dict[str, Any], source: str, index: int) -> dict[str, Any]:
    decision = _approval_decision(item)
    if decision in {"allow", "allowed"}:
        event_type = "agent.approval_granted"
    elif decision in {"blocked", "deny", "denied"}:
        event_type = "agent.approval_denied"
    else:
        event_type = "agent.approval_requested"
    return _event(
        source_kind="approval_broker",
        source=source,
        index=index,
        raw=item,
        event_type=event_type,
        timestamp=_timestamp(item),
        agent=_first(item, "agent", "agent_id", "requester_agent", "workflow", "service"),
        session_id=_first(item, "session_id", "session", "trace_id", "run_id", "request_id", "approval_id", "correlation_id"),
        tool=_first(item, "tool", "tool_name", "action", "operation", "resource"),
        action_class=_first(item, "action_class", "risk_tag", "approval_type"),
        data_classes=string_list(item.get("data_classes")),
        identity=_first(item, "identity", "principal", "requester", "actor"),
        target=_first(item, "target", "resource", "target_system"),
        decision=decision,
        policy=_first(item, "policy", "policy_id", "rule", "control"),
        confidence=str(item.get("confidence") or "high"),
    )


def _event_from_mcp(item: dict[str, Any], source: str, index: int) -> dict[str, Any]:
    server = _first(item, "server", "server_id", "mcp_server")
    tool = _first(item, "tool", "tool_name", "name", "method", "function")
    if server and tool and "." not in tool:
        tool = f"{server}.{tool}"
    return _event(
        source_kind="mcp_host",
        source=source,
        index=index,
        raw=item,
        event_type="agent.tool_call",
        timestamp=_timestamp(item),
        agent=_first(item, "agent", "agent_id", "client", "client_id", "app"),
        session_id=_first(item, "session_id", "session", "trace_id", "request_id", "correlation_id", "run_id"),
        tool=tool,
        action_class=_first(item, "action_class", "risk_tag", "capability"),
        data_classes=string_list(item.get("data_classes")),
        identity=_first(item, "identity", "principal", "user", "service_account"),
        target=_first(item, "target", "target_system", "resource"),
        decision=_decision(item),
        policy=_first(item, "policy", "policy_id", "guardrail", "rule"),
        confidence=str(item.get("confidence") or "high"),
    )


def _event_from_ci(item: dict[str, Any], source: str, index: int) -> dict[str, Any]:
    name = _first(item, "tool", "job", "job_name", "workflow", "workflow_name", "name", "step")
    provider = _first(item, "provider", "system", "ci_system") or "ci"
    tool = name if "." in name else f"{provider}.{name or 'workflow'}"
    conclusion = _first(item, "conclusion", "status", "result", "outcome")
    return _event(
        source_kind="ci_system",
        source=source,
        index=index,
        raw=item,
        event_type="agent.tool_call",
        timestamp=_timestamp(item),
        agent=_first(item, "agent", "actor", "triggered_by", "user", "repository"),
        session_id=_first(item, "session_id", "run_id", "workflow_run_id", "pipeline_id", "build_id", "correlation_id", "id"),
        tool=tool,
        action_class=_action_class(name + " " + conclusion, "ci_cd_write"),
        data_classes=string_list(item.get("data_classes") or ["source_code"]),
        identity=_first(item, "identity", "principal", "actor", "service_account"),
        target=_first(item, "target", "repository", "environment", "ref"),
        decision=_decision({"status": conclusion}),
        policy=_first(item, "policy", "environment_protection_rule", "rule"),
        confidence=str(item.get("confidence") or "medium"),
    )


def _event_from_cloud(item: dict[str, Any], source: str, index: int) -> dict[str, Any]:
    if isinstance(item.get("protoPayload"), dict):
        proto = item["protoPayload"]
    elif any(key in item for key in ["methodName", "serviceName", "authenticationInfo", "authorizationInfo"]):
        proto = item
    else:
        proto = {}
    user_identity = item.get("userIdentity") if isinstance(item.get("userIdentity"), dict) else {}
    auth_info = proto.get("authenticationInfo") if isinstance(proto.get("authenticationInfo"), dict) else {}
    operation = _first(item, "eventName", "operationName", "methodName") or _first(proto, "methodName", "serviceName")
    service = _first(item, "eventSource", "resourceProviderName", "serviceName") or _first(proto, "serviceName")
    target_system = _cloud_target_system(service, item)
    tool = ".".join(part for part in [target_system, operation] if part) or "cloud.audit_event"
    principal = (
        _first(user_identity, "arn", "userName", "principalId", "accountId")
        or _first(auth_info, "principalEmail", "principalSubject")
        or _first(item, "caller", "identity", "principal")
    )
    denied = item.get("errorCode") or item.get("errorMessage") or proto.get("status")
    return _event(
        source_kind="cloud_audit",
        source=source,
        index=index,
        raw=item,
        event_type="agent.tool_call",
        timestamp=_timestamp(item) or _first(proto, "timestamp"),
        agent=_first(item, "agent", "userAgent", "sourceIPAddress", "caller") or principal,
        session_id=_first(item, "session_id", "requestID", "requestId", "eventID", "insertId", "correlationId"),
        tool=tool,
        action_class=_action_class(operation, ""),
        data_classes=string_list(item.get("data_classes")),
        identity=principal,
        target=_first(item, "resource", "resourceName", "resourceGroupName") or _first(proto, "resourceName"),
        decision="blocked" if denied else "allow",
        policy=_first(item, "policy", "authorizationInfo", "errorCode") or str(denied or ""),
        confidence=str(item.get("confidence") or "medium"),
    )


def _event(
    *,
    source_kind: str,
    source: str,
    index: int,
    raw: dict[str, Any],
    event_type: str,
    timestamp: str,
    agent: str,
    session_id: str,
    tool: str,
    action_class: str,
    data_classes: list[str],
    identity: str,
    target: str,
    decision: str,
    policy: str,
    confidence: str,
) -> dict[str, Any]:
    event_id = str(raw.get("id") or raw.get("event_id") or raw.get("eventID") or raw.get("requestID") or "")
    if not event_id:
        event_id = f"{source_kind}-{hashlib.sha256(json.dumps(raw, sort_keys=True, default=str).encode('utf-8')).hexdigest()[:10]}"
    return {
        "id": event_id,
        "event_type": event_type or "agent.tool_call",
        "timestamp": timestamp,
        "agent": agent,
        "session_id": session_id,
        "delegated_by": str(raw.get("delegated_by") or raw.get("delegatedBy") or ""),
        "input_source": str(raw.get("input_source") or raw.get("inputSource") or ""),
        "input_trust": str(raw.get("input_trust") or raw.get("inputTrust") or ""),
        "tool": tool,
        "action_class": action_class or _action_class(tool, ""),
        "data_classes": data_classes,
        "identity": identity,
        "target": target,
        "decision": _canonical_decision(decision),
        "policy": policy,
        "confidence": confidence if confidence in {"high", "medium", "low"} else "medium",
        "source_kind": source_kind,
        "source_file": source,
        "line": index,
        "raw": raw,
    }


def _first(item: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = item.get(key)
        if value is not None and value != "":
            return str(value)
    return ""


def _timestamp(item: dict[str, Any]) -> str:
    return _first(item, "timestamp", "time", "eventTime", "created_at", "createdAt", "started_at", "startTime", "event_timestamp")


def _decision(item: dict[str, Any]) -> str:
    return _canonical_decision(_first(item, "decision", "outcome", "status", "result", "conclusion", "allowed"))


def _approval_decision(item: dict[str, Any]) -> str:
    return _canonical_decision(_first(item, "decision", "approval", "approved", "allowed", "status", "outcome", "result"))


def _canonical_decision(value: str) -> str:
    lowered = str(value or "unknown").lower()
    if lowered in ALLOW_VALUES or lowered == "true":
        return "allow"
    if lowered in DENY_VALUES or lowered == "false":
        return "blocked"
    if lowered in {"pending", "requested", "approval_required", "needs_approval"}:
        return "approval_required"
    return lowered if lowered in {"allow", "allowed", "blocked", "deny", "denied", "unknown"} else "unknown"


def _action_class(value: str, default: str) -> str:
    text = str(value or "").lower()
    if any(word in text for word in ["approve", "payment", "invoice", "vendor"]):
        return "financial_action"
    if any(word in text for word in ["deploy", "apply", "release", "workflow", "pipeline", "build"]):
        return "ci_cd_write"
    if any(word in text for word in WRITE_WORDS):
        return "write_action"
    if any(word in text for word in READ_WORDS):
        return "read_action"
    return default


def _cloud_target_system(service: str, item: dict[str, Any]) -> str:
    text = f"{service} {json.dumps(item, default=str)[:500]}".lower()
    if "amazonaws.com" in text or "aws" in text:
        return "aws"
    if "googleapis.com" in text or "gcp" in text or "google" in text:
        return "gcp"
    if "microsoft" in text or "azure" in text:
        return "azure"
    if "." in service:
        return service.split(".")[0]
    return service or "cloud"
