"""Summaries for policy-as-code and approval policy evidence."""

from __future__ import annotations

from typing import Any

from .adapters.approval_policy import rule_matches
from .offline_analysis import declared_controls_for_policy, required_controls_for_tool
from .schemas import DANGEROUS_TAGS
from .validation.validate_inputs import all_tools


HIGH_RISK_POLICY_TAGS = DANGEROUS_TAGS | {
    "external_message",
    "data_exfiltration_sink",
    "financial_action",
    "network_access",
    "memory_write",
    "sensitive_read",
}


def build_policy_analysis(evidence: dict[str, Any]) -> dict[str, Any]:
    approval = evidence.get("approval_policy") or {}
    policies = approval.get("policies") or []
    evaluations = approval.get("policy_evaluations") or []
    rules = [rule for policy in policies for rule in policy.get("rules", []) if isinstance(rule, dict)]
    engines: dict[str, int] = {}
    decisions = {"allow": 0, "approval_required": 0, "deny": 0, "unknown": 0}
    for evaluation in evaluations:
        engine = str(evaluation.get("engine") or "unknown")
        engines[engine] = engines.get(engine, 0) + 1
        decision = str(evaluation.get("decision") or "unknown")
        decisions[decision if decision in decisions else "unknown"] += 1

    evaluation_rows = [_evaluation_row(evaluation) for evaluation in evaluations]
    gaps = _policy_gaps(evaluation_rows, policies, rules)
    rule_risks = _policy_rule_risks(evidence, policies)
    return {
        "summary": {
            "policies": len(policies),
            "rules": len(rules),
            "policy_evaluations": len(evaluations),
            "policy_as_code_rules": sum(1 for rule in rules if rule.get("policy_engine")),
            "opa_rego_evaluations": engines.get("opa_rego", 0),
            "cedar_evaluations": engines.get("cedar", 0),
            "allow": decisions["allow"],
            "approval_required": decisions["approval_required"],
            "deny": decisions["deny"],
            "unknown": decisions["unknown"],
            "gaps": len(gaps),
            "policy_rule_risks": len(rule_risks),
            "broad_allows": sum(1 for risk in rule_risks if risk["type"] == "broad_allow_high_risk"),
            "shadowed_rules": sum(1 for risk in rule_risks if risk["type"] == "policy_rule_shadowed"),
            "conflicting_decisions": sum(1 for risk in rule_risks if risk["type"] == "conflicting_matching_decisions"),
            "unmatched_policy_rules": sum(1 for risk in rule_risks if risk["type"] == "unmatched_policy_rule"),
            "ineffective_control_rules": sum(1 for risk in rule_risks if risk["type"] == "ineffective_control_rule"),
        },
        "engines": engines,
        "evaluations": evaluation_rows,
        "gaps": gaps,
        "rule_risks": rule_risks,
    }


def _evaluation_row(evaluation: dict[str, Any]) -> dict[str, Any]:
    match = evaluation.get("match") if isinstance(evaluation.get("match"), dict) else {}
    return {
        "id": str(evaluation.get("id", "")),
        "engine": str(evaluation.get("engine", "unknown")),
        "decision": str(evaluation.get("decision", "unknown")),
        "policy": str(evaluation.get("policy") or evaluation.get("package") or evaluation.get("path") or ""),
        "query": str(evaluation.get("query") or ""),
        "match": match,
        "match_keys": sorted(match.keys()),
        "reason": str(evaluation.get("reason") or ""),
        "source_file": str(evaluation.get("source_file") or ""),
        "confidence": str(evaluation.get("confidence") or "medium"),
    }


def _policy_gaps(
    evaluations: list[dict[str, Any]],
    policies: list[dict[str, Any]],
    rules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    gaps = []
    if not policies:
        gaps.append(
            {
                "type": "approval_policy_missing",
                "target": "approval-policy.json",
                "reason": "No approval policy rules are available for graph analysis.",
                "repair": "Import policy evaluations with concrete agent/tool/action context or add approval-policy.json rules.",
            }
        )
    if evaluations and not any(rule.get("policy_engine") for rule in rules):
        gaps.append(
            {
                "type": "policy_evaluation_unmatched",
                "target": "policy_evaluations",
                "reason": "Policy evaluation evidence was imported but no evaluation had enough match context to become a rule.",
                "repair": "Export policy inputs with agent, tool or action, target_system, environment, and data_classes.",
            }
        )
    for evaluation in evaluations:
        if not evaluation.get("match_keys"):
            gaps.append(
                {
                    "type": "policy_evaluation_missing_context",
                    "target": evaluation.get("id", "policy_evaluation"),
                    "reason": f"{evaluation.get('engine', 'policy')} evaluation has no concrete match context.",
                    "repair": "Include the authorization input/request with agent, tool or action, target_system, environment, and data classes.",
                }
            )
        if evaluation.get("decision") == "unknown":
            gaps.append(
                {
                    "type": "policy_evaluation_unknown_decision",
                    "target": evaluation.get("id", "policy_evaluation"),
                    "reason": "The policy result could not be normalized to allow, approval_required, or deny.",
                    "repair": "Export a decision field or a result object with allow, deny, or approval_required.",
                }
            )
    return gaps


def _policy_rule_risks(evidence: dict[str, Any], policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    tools_by_id = {tool["id"]: tool for tool in all_tools(evidence) if tool.get("id")}
    risks: list[dict[str, Any]] = []
    contexts: list[dict[str, Any]] = []
    matched_rule_keys: set[tuple[str, int]] = set()
    for agent in (evidence.get("agents") or {}).get("agents", []):
        policy_id = str(agent.get("approval_policy") or "")
        candidate_policies = [policy for policy in policies if policy.get("id") == policy_id] if policy_id else policies
        for tool_id in agent.get("tools", []):
            tool = tools_by_id.get(tool_id)
            if not tool:
                continue
            context = _policy_context(agent, tool)
            contexts.append(
                {
                    "agent": agent,
                    "tool": tool,
                    "policy_id": policy_id,
                    "context": context,
                    "candidate_policies": candidate_policies,
                }
            )
            matching = _matching_rules(candidate_policies, context)
            matched_rule_keys.update((item["policy"], item["index"]) for item in matching)
            if not matching:
                continue
            risks.extend(_risks_for_matching_rules(agent, tool, matching))
    risks.extend(_risks_for_policy_inventory(policies, contexts, matched_rule_keys))
    return sorted(
        risks,
        key=lambda item: (
            item["type"],
            item.get("policy", ""),
            item.get("agent", ""),
            item.get("tool", ""),
            item.get("rule", ""),
            item.get("effective_rule", ""),
        ),
    )


def _policy_context(agent: dict[str, Any], tool: dict[str, Any]) -> dict[str, Any]:
    risk_tags = tool.get("risk_tags", [])
    return {
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
    }


def _matching_rules(policies: list[dict[str, Any]], context: dict[str, Any]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for policy in policies:
        for index, rule in enumerate(policy.get("rules", [])):
            match = rule.get("match") if isinstance(rule.get("match"), dict) else {}
            if rule_matches(match, context):
                matches.append(
                    {
                        "policy": str(policy.get("id", "")),
                        "rule": str(rule.get("id", "")),
                        "index": index,
                        "decision": str(rule.get("decision", "unknown")),
                        "match": match,
                        "match_keys": sorted(match.keys()),
                        "controls": [str(control) for control in rule.get("controls", []) if control],
                        "source_file": str(rule.get("source_file", "")),
                    }
                )
    return matches


def _risks_for_policy_inventory(
    policies: list[dict[str, Any]],
    contexts: list[dict[str, Any]],
    matched_rule_keys: set[tuple[str, int]],
) -> list[dict[str, Any]]:
    risks: list[dict[str, Any]] = []
    for policy in policies:
        policy_id = str(policy.get("id", ""))
        policy_contexts = _contexts_for_policy(policy_id, contexts)
        for index, rule in enumerate(policy.get("rules", [])):
            rule_info = _rule_info(policy_id, index, rule)
            if (policy_id, index) not in matched_rule_keys:
                risks.append(_unmatched_policy_rule_risk(rule_info, bool(policy_contexts)))
                if _declares_high_risk_controls(rule_info):
                    risks.append(_unmatched_control_rule_risk(rule_info))
                continue
            for item in policy_contexts:
                if rule_matches(rule_info["match"], item["context"]):
                    ineffective = _matched_ineffective_control_risk(
                        item["agent"],
                        item["tool"],
                        rule_info,
                    )
                    if ineffective:
                        risks.append(ineffective)
    return risks


def _contexts_for_policy(policy_id: str, contexts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        item
        for item in contexts
        if not item.get("policy_id") or item.get("policy_id") == policy_id
    ]


def _rule_info(policy_id: str, index: int, rule: dict[str, Any]) -> dict[str, Any]:
    match = rule.get("match") if isinstance(rule.get("match"), dict) else {}
    return {
        "policy": policy_id,
        "rule": str(rule.get("id", "")),
        "index": index,
        "decision": str(rule.get("decision", "unknown")),
        "match": match,
        "match_keys": sorted(match.keys()),
        "controls": [str(control) for control in rule.get("controls", []) if control],
        "source_file": str(rule.get("source_file", "")),
    }


def _unmatched_policy_rule_risk(rule: dict[str, Any], has_policy_contexts: bool) -> dict[str, Any]:
    policy_context_reason = (
        "The rule did not match any known agent-tool context for its policy."
        if has_policy_contexts
        else "No known agent-tool context uses this policy, so none of its rules can currently match."
    )
    return {
        "type": "unmatched_policy_rule",
        "policy": rule["policy"],
        "rule": rule["rule"],
        "decision": rule["decision"],
        "match_keys": rule["match_keys"],
        "source_file": rule["source_file"],
        "reason": policy_context_reason,
        "repair": "Fix stale agent/tool ids or match keys, remove the dead rule, or attach agents to this policy.",
    }


def _unmatched_control_rule_risk(rule: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "ineffective_control_rule",
        "policy": rule["policy"],
        "rule": rule["rule"],
        "decision": rule["decision"],
        "match_keys": rule["match_keys"],
        "source_file": rule["source_file"],
        "reason": "The rule declares controls for high-risk actions but never matches current local evidence.",
        "repair": "Correct the match expression so the control rule reaches the intended high-risk agent-tool context.",
    }


def _matched_ineffective_control_risk(
    agent: dict[str, Any],
    tool: dict[str, Any],
    rule: dict[str, Any],
) -> dict[str, Any] | None:
    explicit_controls = set(rule.get("controls", []))
    if not explicit_controls:
        return None
    required = set(required_controls_for_tool(tool))
    if not required:
        return None
    relevant_controls = explicit_controls.intersection(required)
    if relevant_controls:
        return None
    declared = declared_controls_for_policy({"decision": rule["decision"], "controls": rule["controls"]})
    return {
        "type": "ineffective_control_rule",
        "policy": rule["policy"],
        "rule": rule["rule"],
        "decision": rule["decision"],
        "agent": str(agent.get("id", "")),
        "tool": str(tool.get("id", "")),
        "effective_decision": rule["decision"],
        "match_keys": rule["match_keys"],
        "source_file": rule["source_file"],
        "reason": (
            "The rule matches a high-risk tool but declares only controls that are not required for that tool."
        ),
        "repair": (
            "Replace irrelevant controls with required controls for this tool: "
            f"{', '.join(sorted(required))}."
        ),
        "declared_controls": declared,
        "required_controls": sorted(required),
    }


def _declares_high_risk_controls(rule: dict[str, Any]) -> bool:
    if not rule.get("controls"):
        return False
    if _match_targets_high_risk(rule.get("match", {})):
        return True
    high_risk_controls = {
        "approval_required",
        "sandbox_control",
        "egress_allowlist",
        "scoped_identity",
        "command_allowlist",
        "secret_denylist",
        "amount_threshold",
        "audit_logging",
        "change_ticket_required",
        "dlp_redaction",
    }
    return bool(set(rule.get("controls", [])).intersection(high_risk_controls))


def _match_targets_high_risk(match: dict[str, Any]) -> bool:
    values: list[str] = []
    for key in ("risk_tag", "action_class"):
        value = match.get(key)
        if isinstance(value, list):
            values.extend(str(item) for item in value)
        elif value:
            values.append(str(value))
    return bool(set(values).intersection(HIGH_RISK_POLICY_TAGS))


def _risks_for_matching_rules(
    agent: dict[str, Any],
    tool: dict[str, Any],
    matching: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    first = matching[0]
    risk_tags = [str(tag) for tag in tool.get("risk_tags", [])]
    high_risk = bool(set(risk_tags).intersection(HIGH_RISK_POLICY_TAGS))
    risks: list[dict[str, Any]] = []
    if high_risk and first["decision"] == "allow" and _weak_match_scope(first.get("match", {})):
        risks.append(
            _rule_risk(
                "broad_allow_high_risk",
                agent,
                tool,
                first,
                matching,
                "A broad allow rule is the effective decision for a high-risk tool.",
                "Scope the rule to agent, tool, target_system, and environment, or require approval/deny for this action.",
            )
        )
    decisions = {item["decision"] for item in matching}
    if len(decisions) > 1:
        risks.append(
            _rule_risk(
                "conflicting_matching_decisions",
                agent,
                tool,
                first,
                matching,
                "Multiple matching policy rules produce different decisions for the same agent-tool context.",
                "Reorder or narrow policy rules so only the intended decision matches this context.",
            )
        )
    for later in matching[1:]:
        if later["decision"] != first["decision"]:
            risks.append(
                _rule_risk(
                    "policy_rule_shadowed",
                    agent,
                    tool,
                    first,
                    [later],
                    "A later matching rule has a different decision but is shadowed by the first matching rule.",
                    "Move the narrower rule earlier or make the broad rule more specific.",
                    shadowed_rule=later["rule"],
                    shadowed_decision=later["decision"],
                )
            )
    return risks


def _weak_match_scope(match: dict[str, Any]) -> bool:
    keys = set(match.keys())
    if not keys:
        return True
    return not ({"agent", "tool"}.issubset(keys) or {"tool", "environment"}.issubset(keys))


def _rule_risk(
    risk_type: str,
    agent: dict[str, Any],
    tool: dict[str, Any],
    effective: dict[str, Any],
    matching: list[dict[str, Any]],
    reason: str,
    repair: str,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "type": risk_type,
        "policy": effective.get("policy", ""),
        "rule": effective.get("rule", ""),
        "decision": effective.get("decision", "unknown"),
        "agent": str(agent.get("id", "")),
        "tool": str(tool.get("id", "")),
        "target_system": str(tool.get("target_system", "unknown")),
        "environment": str(agent.get("environment", "unknown")),
        "risk_tags": tool.get("risk_tags", []),
        "effective_policy": effective.get("policy", ""),
        "effective_rule": effective.get("rule", ""),
        "effective_decision": effective.get("decision", "unknown"),
        "match_keys": effective.get("match_keys", []),
        "matching_rules": [
            {
                "policy": item.get("policy", ""),
                "rule": item.get("rule", ""),
                "decision": item.get("decision", "unknown"),
                "match_keys": item.get("match_keys", []),
            }
            for item in matching
        ],
        "reason": reason,
        "repair": repair,
        "source_file": effective.get("source_file", ""),
        **extra,
    }
