"""Approval policy evidence parser and matcher."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..schemas import load_json_file, source_name, string_list


def parse_approval_policy(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {"schema_version": "0.1", "policies": [], "source_file": None, "warnings": []}
    data = load_json_file(path)
    source = source_name(path)
    warnings = []
    policies = []
    for policy_index, policy in enumerate(_list_value(data, "policies", source, warnings)):
        if not isinstance(policy, dict):
            warnings.append(f"{source}: policies[{policy_index}] must be an object")
            continue
        policy_id = str(policy.get("id", ""))
        if not policy_id:
            warnings.append(f"{source}: policies[{policy_index}] is missing id")
        rules = []
        raw_rules = policy.get("rules", [])
        if raw_rules is None:
            raw_rules = []
        elif not isinstance(raw_rules, list):
            warnings.append(f"{source}: policy {policy_id or policy_index} rules must be a list")
            raw_rules = []
        for rule_index, rule in enumerate(raw_rules):
            if not isinstance(rule, dict):
                warnings.append(f"{source}: policy {policy_id or policy_index} rules[{rule_index}] must be an object")
                continue
            rule_id = str(rule.get("id", ""))
            if not rule_id:
                warnings.append(f"{source}: policy {policy_id or policy_index} rules[{rule_index}] is missing id")
            match = rule.get("match", {})
            if match is None:
                match = {}
            elif not isinstance(match, dict):
                warnings.append(f"{source}: policy {policy_id or policy_index} rule {rule_id or rule_index} match must be an object")
                match = {}
            if rule.get("controls") is not None and not isinstance(rule.get("controls"), list):
                warnings.append(f"{source}: policy {policy_id or policy_index} rule {rule_id or rule_index} controls should be a list")
            rules.append(
                {
                    "id": rule_id,
                    "match": match,
                    "decision": str(rule.get("decision", "unknown")),
                    "reason": str(rule.get("reason", "")),
                    "controls": string_list(rule.get("controls")),
                    "policy_engine": str(rule.get("policy_engine", "")),
                    "evaluation_id": str(rule.get("evaluation_id", "")),
                    "source_file": source,
                    "raw": rule,
                }
            )
        policies.append(
            {
                "id": policy_id,
                "engine": str(policy.get("engine", "")),
                "rules": rules,
                "source_file": source,
                "raw": policy,
            }
        )
    return {
        "schema_version": str(data.get("schema_version", "0.1")),
        "policies": policies,
        "policy_evaluations": _policy_evaluations(data, source, warnings),
        "source_file": source,
        "warnings": warnings,
    }


def _policy_evaluations(data: dict[str, Any], source: str, warnings: list[str]) -> list[dict[str, Any]]:
    evaluations = []
    for index, evaluation in enumerate(_list_value(data, "policy_evaluations", source, warnings)):
        if not isinstance(evaluation, dict):
            warnings.append(f"{source}: policy_evaluations[{index}] must be an object")
            continue
        normalized = dict(evaluation)
        normalized.setdefault("source_file", source)
        normalized["engine"] = str(normalized.get("engine", ""))
        normalized["decision"] = str(normalized.get("decision", "unknown"))
        match = normalized.get("match", {})
        if match is None:
            match = {}
        elif not isinstance(match, dict):
            warnings.append(f"{source}: policy_evaluations[{index}] match must be an object")
            match = {}
        normalized["match"] = match
        evaluations.append(normalized)
    return evaluations


def _list_value(data: dict[str, Any], key: str, source: str, warnings: list[str]) -> list[Any]:
    value = data.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list):
        warnings.append(f"{source}: {key} must be a list")
        return []
    return value


def _contains_any(actual: list[str], expected: list[str]) -> bool:
    return bool(set(actual).intersection(expected))


def _match_scalar_or_list(actual: Any, expected: Any) -> bool:
    if expected is None:
        return True
    if isinstance(expected, list):
        return str(actual) in {str(item) for item in expected}
    return str(actual) == str(expected)


def rule_matches(rule_match: dict[str, Any], context: dict[str, Any]) -> bool:
    for key, expected in rule_match.items():
        if key == "data_classes_any":
            if not _contains_any([str(item) for item in context.get("data_classes", [])], [str(item) for item in expected]):
                return False
        elif key == "risk_tag":
            risk_tags = [str(item) for item in context.get("risk_tags", [])]
            expected_values = [str(item) for item in expected] if isinstance(expected, list) else [str(expected)]
            if not _contains_any(risk_tags, expected_values):
                return False
        elif key == "action_class":
            action_classes = set(context.get("risk_tags", []))
            action_classes.add(str(context.get("action_class", "")))
            expected_values = [str(item) for item in expected] if isinstance(expected, list) else [str(expected)]
            if not action_classes.intersection(expected_values):
                return False
        else:
            if not _match_scalar_or_list(context.get(key, ""), expected):
                return False
    return True


def evaluate_policy(policies: list[dict[str, Any]], policy_id: str, context: dict[str, Any]) -> dict[str, Any]:
    """Return the first matching policy rule for a context."""
    candidates = [policy for policy in policies if policy.get("id") == policy_id] if policy_id else policies
    for policy in candidates:
        for rule in policy.get("rules", []):
            if rule_matches(rule.get("match", {}), context):
                return {
                    "decision": rule.get("decision", "unknown"),
                    "policy": policy.get("id", ""),
                    "rule": rule.get("id", ""),
                    "reason": rule.get("reason", ""),
                    "controls": rule.get("controls", []),
                    "policy_engine": rule.get("policy_engine", "") or policy.get("engine", ""),
                    "evaluation_id": rule.get("evaluation_id", ""),
                    "source_file": rule.get("source_file", ""),
                }
    return {"decision": "unknown", "policy": policy_id or "", "rule": "", "reason": "no matching approval rule", "controls": []}
