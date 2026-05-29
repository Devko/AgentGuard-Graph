"""Import OPA/Rego and Cedar policy evidence into approval policy records."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from ..errors import EvidenceLoadError
from ..schemas import CONTROL_TAGS, infer_target_system, source_name, string_list


MATCH_FIELDS = {
    "agent",
    "tool",
    "action_class",
    "target_system",
    "environment",
    "external_target",
    "risk_tag",
    "data_classes_any",
}


FIELD_ALIASES = {
    "agent": ["agent", "agent_id", "agentId", "workflow", "app", "application"],
    "tool": ["tool", "tool_id", "toolId", "tool_name", "toolName", "function", "operation", "operationId"],
    "action_class": ["action_class", "actionClass", "action", "operation_type", "operationType"],
    "target_system": ["target_system", "targetSystem", "service", "system", "platform", "provider"],
    "environment": ["environment", "env"],
    "external_target": ["external_target", "externalTarget", "recipient_type", "recipientType", "target"],
}


DECISION_HINTS = {
    "allow": "allow",
    "allowed": "allow",
    "permit": "allow",
    "permitted": "allow",
    "approve": "allow",
    "deny": "deny",
    "denied": "deny",
    "forbid": "deny",
    "forbidden": "deny",
    "block": "deny",
    "blocked": "deny",
    "disallow": "deny",
    "approval_required": "approval_required",
    "requires_approval": "approval_required",
    "manual_review": "approval_required",
    "review": "approval_required",
}


def parse_opa_policy(path: str | Path) -> dict[str, Any]:
    """Parse Rego source, OPA eval JSON, or OPA decision logs."""
    payload, source, suffix = _load_policy_input(path, "OPA/Rego policy evidence")
    if suffix == ".rego" or isinstance(payload, str):
        return _result("opa_rego", source, _evaluations_from_rego_source(str(payload), source))
    return _result("opa_rego", source, _evaluations_from_opa_json(payload, source))


def parse_cedar_policy(path: str | Path) -> dict[str, Any]:
    """Parse Cedar policy source or Cedar authorization result JSON."""
    payload, source, suffix = _load_policy_input(path, "Cedar policy evidence")
    if suffix == ".cedar" or isinstance(payload, str):
        return _result("cedar", source, _evaluations_from_cedar_source(str(payload), source))
    return _result("cedar", source, _evaluations_from_cedar_json(payload, source))


def _load_policy_input(path: str | Path, label: str) -> tuple[Any, str, str]:
    evidence_path = Path(path)
    if not evidence_path.exists():
        raise EvidenceLoadError(f"{evidence_path}: {label} file not found")
    suffix = evidence_path.suffix.lower()
    try:
        text = evidence_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceLoadError(f"{evidence_path}: cannot decode as UTF-8: {exc.reason}") from exc
    except OSError as exc:
        raise EvidenceLoadError(f"{evidence_path}: cannot read file: {exc}") from exc
    if suffix == ".json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise EvidenceLoadError(f"{evidence_path}:{exc.lineno}:{exc.colno}: invalid JSON: {exc.msg}") from exc
        if not isinstance(payload, (dict, list)):
            raise EvidenceLoadError(f"{evidence_path}: {label} JSON must be an object or array")
        return payload, source_name(evidence_path), suffix
    return text, source_name(evidence_path), suffix


def _result(engine: str, source: str, evaluations: list[dict[str, Any]]) -> dict[str, Any]:
    clean = [item for item in evaluations if item]
    rules = [_rule_from_evaluation(item, index) for index, item in enumerate(clean, start=1)]
    rules = [rule for rule in rules if rule]
    policy_id = _policy_id(engine, source, clean)
    warnings = []
    if not clean:
        warnings.append(f"{source}: no {engine} policy evaluations were extracted")
    if clean and not rules:
        warnings.append(f"{source}: policy evaluations did not contain concrete match context for approval rules")
    return {
        "kind": engine,
        "source_file": source,
        "policies": (
            [
                {
                    "id": policy_id,
                    "engine": engine,
                    "source_file": source,
                    "rules": rules,
                }
            ]
            if rules
            else []
        ),
        "policy_evaluations": clean,
        "warnings": warnings,
    }


def _policy_id(engine: str, source: str, evaluations: list[dict[str, Any]]) -> str:
    for evaluation in evaluations:
        candidate = evaluation.get("policy") or evaluation.get("package") or evaluation.get("query") or evaluation.get("path")
        if candidate:
            return f"{engine}:{_safe_id(str(candidate))}"
    return f"{engine}:{_safe_id(Path(source).stem)}"


def _rule_from_evaluation(evaluation: dict[str, Any], index: int) -> dict[str, Any]:
    decision = str(evaluation.get("decision") or "unknown")
    match = evaluation.get("match") if isinstance(evaluation.get("match"), dict) else {}
    if decision == "unknown" or not _specific_match(match):
        return {}
    controls = [item for item in string_list(evaluation.get("controls")) if item in CONTROL_TAGS]
    return {
        "id": evaluation.get("rule") or f"{evaluation.get('engine', 'policy')}-{index}-{decision}",
        "match": match,
        "decision": decision,
        "reason": evaluation.get("reason")
        or f"Imported {evaluation.get('engine', 'policy')} evaluation returned {decision}.",
        "controls": controls,
        "policy_engine": evaluation.get("engine", ""),
        "evaluation_id": evaluation.get("id", ""),
        "source_file": evaluation.get("source_file", ""),
        "raw": evaluation.get("raw", {}),
    }


def _evaluation(
    *,
    engine: str,
    source: str,
    index: int,
    decision: str,
    match: dict[str, Any],
    raw: Any,
    policy: str = "",
    query: str = "",
    path: str = "",
    package: str = "",
    reason: str = "",
    controls: list[str] | None = None,
    confidence: str = "medium",
) -> dict[str, Any]:
    raw_payload = raw if isinstance(raw, (dict, list, str, bool, int, float, type(None))) else str(raw)
    evaluation_id = _stable_id(
        {
            "engine": engine,
            "source": source,
            "index": index,
            "decision": decision,
            "match": match,
            "policy": policy,
            "query": query,
            "path": path,
        }
    )
    return {
        "id": evaluation_id,
        "engine": engine,
        "source_file": source,
        "policy": policy,
        "query": query,
        "path": path,
        "package": package,
        "decision": decision,
        "match": _clean_match(match),
        "reason": reason,
        "controls": controls or [],
        "confidence": confidence,
        "raw": raw_payload,
    }


def _evaluations_from_opa_json(payload: Any, source: str) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and _is_opa_eval_result(payload):
        return _opa_eval_result_records(payload, source)
    records = _records(payload, ["decisions", "decision_logs", "evaluations", "results", "items", "records"])
    return [_evaluation_from_opa_record(record, source, index) for index, record in enumerate(records, start=1)]


def _is_opa_eval_result(payload: dict[str, Any]) -> bool:
    results = payload.get("result")
    return isinstance(results, list) and any(isinstance(item, dict) and isinstance(item.get("expressions"), list) for item in results)


def _opa_eval_result_records(payload: dict[str, Any], source: str) -> list[dict[str, Any]]:
    evaluations: list[dict[str, Any]] = []
    base_input = payload.get("input") if isinstance(payload.get("input"), dict) else {}
    query = str(payload.get("query") or payload.get("path") or "")
    for result_index, result in enumerate(payload.get("result", []), start=1):
        if not isinstance(result, dict):
            continue
        context = result.get("input") if isinstance(result.get("input"), dict) else base_input
        for expression_index, expression in enumerate(result.get("expressions", []), start=1):
            if not isinstance(expression, dict):
                continue
            expression_query = str(expression.get("text") or query)
            value = expression.get("value")
            decision = _decision_from_value(value, expression_query)
            evaluations.append(
                _evaluation(
                    engine="opa_rego",
                    source=source,
                    index=(result_index * 1000) + expression_index,
                    decision=decision,
                    match=_match_from_context(context),
                    raw=expression,
                    query=expression_query,
                    path=str(payload.get("path") or ""),
                    reason=_reason_from_value(value),
                    confidence="high" if decision != "unknown" else "medium",
                )
            )
    return evaluations


def _evaluation_from_opa_record(record: dict[str, Any], source: str, index: int) -> dict[str, Any]:
    result = record.get("result", record.get("decision", record.get("value")))
    decision = _decision_from_value(result, str(record.get("path") or record.get("query") or record.get("rule") or ""))
    context = record.get("input") if isinstance(record.get("input"), dict) else record.get("request")
    if not isinstance(context, dict):
        context = record
    return _evaluation(
        engine="opa_rego",
        source=source,
        index=index,
        decision=decision,
        match=_match_from_context(context),
        raw=record,
        policy=str(record.get("policy") or record.get("package") or ""),
        query=str(record.get("query") or ""),
        path=str(record.get("path") or ""),
        package=str(record.get("package") or ""),
        reason=_reason_from_value(result) or str(record.get("reason") or ""),
        controls=_controls_from_record(record),
        confidence="high" if decision != "unknown" else "medium",
    )


def _evaluations_from_cedar_json(payload: Any, source: str) -> list[dict[str, Any]]:
    records = _records(payload, ["authorization_results", "authorizations", "decisions", "evaluations", "results", "items", "records"])
    return [_evaluation_from_cedar_record(record, source, index) for index, record in enumerate(records, start=1)]


def _evaluation_from_cedar_record(record: dict[str, Any], source: str, index: int) -> dict[str, Any]:
    request = record.get("request") if isinstance(record.get("request"), dict) else record.get("input")
    if not isinstance(request, dict):
        request = record
    decision = _decision_from_value(record.get("decision", record.get("result")), "cedar authorize")
    diagnostics = record.get("diagnostics") if isinstance(record.get("diagnostics"), dict) else {}
    reason_values = diagnostics.get("reason") or diagnostics.get("reasons") or record.get("reason")
    return _evaluation(
        engine="cedar",
        source=source,
        index=index,
        decision=decision,
        match=_match_from_context(request),
        raw=record,
        policy=str(record.get("policy") or record.get("policy_id") or ""),
        reason=", ".join(string_list(reason_values)),
        controls=_controls_from_record(record),
        confidence="high" if decision != "unknown" else "medium",
    )


def _evaluations_from_rego_source(text: str, source: str) -> list[dict[str, Any]]:
    package = _first_regex(text, r"(?m)^\s*package\s+([A-Za-z0-9_.-]+)")
    evaluations: list[dict[str, Any]] = []
    seen_spans: set[tuple[int, int]] = set()
    for index, match in enumerate(
        re.finditer(
            r"(?m)^\s*(allow|deny|approval_required|requires_approval)[A-Za-z0-9_]*(?:\[[^\]]+\])?\s*(?:if\s*)?\{",
            text,
        ),
        start=1,
    ):
        start = match.start()
        brace = text.find("{", match.start(), match.end())
        end = _matching_brace(text, brace)
        if end <= brace:
            continue
        seen_spans.add((start, end))
        block = text[start : end + 1]
        rule_name = match.group(1)
        decision = _decision_from_rule_name(rule_name)
        evaluations.append(
            _evaluation(
                engine="opa_rego",
                source=source,
                index=index,
                decision=decision,
                match=_match_from_rego_text(block),
                raw=block,
                policy=package,
                package=package,
                query=rule_name,
                reason=f"Static Rego rule {rule_name} imported from {package or source}.",
                confidence="medium",
            )
        )
    line_index = len(evaluations) + 1
    for match in re.finditer(
        r"(?m)^\s*(allow|deny|approval_required|requires_approval)[A-Za-z0-9_]*(?:\[[^\]]+\])?\s+if\s+([^\n{]+)$",
        text,
    ):
        span = match.span()
        if any(span[0] >= start and span[1] <= end for start, end in seen_spans):
            continue
        rule_name = match.group(1)
        expression = match.group(0)
        evaluations.append(
            _evaluation(
                engine="opa_rego",
                source=source,
                index=line_index,
                decision=_decision_from_rule_name(rule_name),
                match=_match_from_rego_text(expression),
                raw=expression,
                policy=package,
                package=package,
                query=rule_name,
                reason=f"Static Rego rule {rule_name} imported from {package or source}.",
                confidence="low",
            )
        )
        line_index += 1
    return evaluations


def _evaluations_from_cedar_source(text: str, source: str) -> list[dict[str, Any]]:
    evaluations: list[dict[str, Any]] = []
    policy_set = _first_regex(text, r"(?m)^\s*@id\(\"([^\"]+)\"\)")
    pattern = re.compile(r"(?is)\b(permit|forbid)\s*\((.*?)\)\s*(?:when\s*\{(.*?)\})?\s*;")
    for index, match in enumerate(pattern.finditer(text), start=1):
        effect = match.group(1).lower()
        body = f"{match.group(2) or ''}\n{match.group(3) or ''}"
        decision = "allow" if effect == "permit" else "deny"
        evaluations.append(
            _evaluation(
                engine="cedar",
                source=source,
                index=index,
                decision=decision,
                match=_match_from_cedar_text(body),
                raw=match.group(0),
                policy=policy_set,
                reason=f"Static Cedar {effect} policy imported.",
                confidence="medium",
            )
        )
    return evaluations


def _match_from_rego_text(text: str) -> dict[str, Any]:
    match: dict[str, Any] = {}
    for field in ["agent", "tool", "action_class", "target_system", "environment", "external_target"]:
        value = _first_regex(text, rf'input\.{field}\s*==\s*"([^"]+)"')
        if value:
            match[field] = value
    risk_tags = re.findall(r'input\.risk_tags\[_\]\s*==\s*"([^"]+)"', text)
    if risk_tags:
        match["risk_tag"] = sorted(set(risk_tags))
    data_classes = re.findall(r'input\.data_classes\[_\]\s*==\s*"([^"]+)"', text)
    if data_classes:
        match["data_classes_any"] = sorted(set(data_classes))
    return _clean_match(match)


def _match_from_cedar_text(text: str) -> dict[str, Any]:
    match: dict[str, Any] = {}
    action = _first_regex(text, r'action\s*(?:==|in)\s*Action::"([^"]+)"')
    if action:
        _set_action_match(match, action)
    principal = _first_regex(text, r'principal\s*==\s*(?:Agent|User)::"([^"]+)"')
    if principal:
        match["agent"] = principal
    for field, value in re.findall(r'context\.([A-Za-z_][A-Za-z0-9_]*)\s*==\s*"([^"]+)"', text):
        normalized = _context_field_name(field)
        if normalized == "data_classes_any":
            match.setdefault("data_classes_any", []).append(value)
        elif normalized:
            match[normalized] = value
    for value in re.findall(r'context\.data_classes\.contains\("([^"]+)"\)', text):
        match.setdefault("data_classes_any", []).append(value)
    return _clean_match(match)


def _match_from_context(context: dict[str, Any]) -> dict[str, Any]:
    match: dict[str, Any] = {}
    request = context.get("request") if isinstance(context.get("request"), dict) else {}
    context_values = context.get("context") if isinstance(context.get("context"), dict) else {}
    merged = {**request, **context, **context_values}
    for field, aliases in FIELD_ALIASES.items():
        value = _find_scalar(merged, aliases)
        if value:
            if field == "action_class":
                _set_action_match(match, value)
            else:
                match[field] = value
    risk_tags = _find_list(merged, ["risk_tags", "riskTags", "tags"])
    if risk_tags:
        match["risk_tag"] = risk_tags
    data_classes = _find_list(merged, ["data_classes", "dataClasses", "data_class", "classification"])
    if data_classes:
        match["data_classes_any"] = data_classes
    action = _find_action(merged)
    if action and "tool" not in match and "action_class" not in match:
        _set_action_match(match, action)
    if "target_system" not in match:
        inferred = infer_target_system(" ".join(str(match.get(key, "")) for key in ["tool", "action_class"]))
        if inferred != "unknown":
            match["target_system"] = inferred
    return _clean_match(match)


def _find_scalar(item: Any, aliases: list[str], depth: int = 0) -> str:
    if depth > 4:
        return ""
    if isinstance(item, dict):
        for key in aliases:
            value = item.get(key)
            if isinstance(value, (str, int, float, bool)) and value != "":
                return str(value)
            if isinstance(value, dict):
                nested = _first_present(value, ["id", "name", "value", "type"])
                if nested:
                    return nested
        for key, value in item.items():
            if key in {"raw", "result", "diagnostics"}:
                continue
            found = _find_scalar(value, aliases, depth + 1)
            if found:
                return found
    if isinstance(item, list):
        for value in item:
            found = _find_scalar(value, aliases, depth + 1)
            if found:
                return found
    return ""


def _find_list(item: Any, aliases: list[str], depth: int = 0) -> list[str]:
    if depth > 4:
        return []
    if isinstance(item, dict):
        for key in aliases:
            if key not in item:
                continue
            value = item[key]
            values = string_list(value)
            if values:
                return sorted(set(values))
        for key, value in item.items():
            if key in {"raw", "result", "diagnostics"}:
                continue
            found = _find_list(value, aliases, depth + 1)
            if found:
                return found
    if isinstance(item, list):
        for value in item:
            found = _find_list(value, aliases, depth + 1)
            if found:
                return found
    return []


def _find_action(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    action = item.get("action")
    if isinstance(action, dict):
        return _first_present(action, ["id", "name", "type"])
    if isinstance(action, str):
        return action
    return ""


def _first_present(item: dict[str, Any], keys: list[str]) -> str:
    for key in keys:
        value = item.get(key)
        if isinstance(value, (str, int, float, bool)) and value != "":
            return str(value)
    return ""


def _context_field_name(field: str) -> str:
    normalized = field.replace("-", "_")
    if normalized == "data_class" or normalized == "data_classes":
        return "data_classes_any"
    for target, aliases in FIELD_ALIASES.items():
        if normalized in {alias.replace("-", "_") for alias in aliases}:
            return target
    return normalized if normalized in MATCH_FIELDS else ""


def _set_action_match(match: dict[str, Any], value: str) -> None:
    action = str(value)
    if "." in action or ":" in action:
        match["tool"] = action
        return
    match["action_class"] = action


def _decision_from_rule_name(rule_name: str) -> str:
    lowered = rule_name.lower()
    if lowered.startswith("deny") or lowered.startswith("forbid"):
        return "deny"
    if lowered.startswith("approval") or lowered.startswith("requires_approval"):
        return "approval_required"
    if lowered.startswith("allow") or lowered.startswith("permit"):
        return "allow"
    return "unknown"


def _decision_from_value(value: Any, hint: str = "") -> str:
    if isinstance(value, dict):
        for key in ["decision", "effect", "result", "outcome"]:
            decision = _normalize_decision(value.get(key))
            if decision != "unknown":
                return decision
        for key in ["approval_required", "requires_approval", "manual_review"]:
            if value.get(key) is True:
                return "approval_required"
        for key in ["deny", "denied", "forbid", "blocked"]:
            candidate = value.get(key)
            if candidate is True or (isinstance(candidate, list) and candidate):
                return "deny"
        for key in ["allow", "allowed", "permit", "permitted"]:
            if value.get(key) is True:
                return "allow"
        return "unknown"
    if isinstance(value, bool):
        if not value:
            return "unknown"
        lowered = hint.lower()
        if any(word in lowered for word in ["deny", "forbid", "block", "disallow"]):
            return "deny"
        if any(word in lowered for word in ["approval", "review"]):
            return "approval_required"
        return "allow"
    return _normalize_decision(value)


def _normalize_decision(value: Any) -> str:
    text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return DECISION_HINTS.get(text, "unknown")


def _reason_from_value(value: Any) -> str:
    if isinstance(value, dict):
        reason = value.get("reason") or value.get("message") or value.get("explanation")
        if reason:
            return str(reason)
        reasons = value.get("reasons")
        if reasons:
            return ", ".join(string_list(reasons))
    return ""


def _controls_from_record(record: dict[str, Any]) -> list[str]:
    values = string_list(record.get("controls") or record.get("control") or record.get("control_tags"))
    return sorted({value for value in values if value in CONTROL_TAGS})


def _records(payload: Any, keys: list[str]) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    if _looks_like_decision_record(payload):
        return [payload]
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = _records(value, keys)
            if nested:
                return nested
    for key, value in payload.items():
        if isinstance(value, list) and key.lower() in {item.lower() for item in keys}:
            return [item for item in value if isinstance(item, dict)]
    return [payload]


def _looks_like_decision_record(payload: dict[str, Any]) -> bool:
    return any(key in payload for key in ["decision", "decision_id", "result", "effect", "input", "request"])


def _clean_match(match: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in match.items():
        if key not in MATCH_FIELDS:
            continue
        if isinstance(value, list):
            values = sorted({str(item) for item in value if item not in {"", None}})
            if values:
                clean[key] = values
        elif value not in {"", None}:
            clean[key] = str(value)
    return clean


def _specific_match(match: dict[str, Any]) -> bool:
    for value in match.values():
        if value in {"", None}:
            continue
        if isinstance(value, list) and not value:
            continue
        return True
    return False


def _matching_brace(text: str, start: int) -> int:
    depth = 0
    in_string = False
    escape = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _first_regex(text: str, pattern: str) -> str:
    match = re.search(pattern, text)
    return match.group(1) if match else ""


def _safe_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]+", "-", value).strip("-")
    return cleaned or "policy"


def _stable_id(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    return "policy-eval-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
