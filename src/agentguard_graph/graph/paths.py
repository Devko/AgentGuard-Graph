"""Attack-path rule evaluation."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ..adapters.approval_policy import evaluate_policy
from ..models import AttackPath, Finding, ScoreResult, VisibilityGap, confidence_max
from ..offline_analysis import build_offline_control_analysis, control_label
from ..schemas import DANGEROUS_TAGS, SENSITIVE_DATA_CLASSES, edge_id, node_id
from ..validation.validate_inputs import all_tools, source_files
from .builder import build_inventory
from .scoring import score_path, tier_for_score

IAM_VISIBILITY_TARGET_SYSTEMS = {
    "aws",
    "azure",
    "confluence",
    "databricks",
    "dataverse",
    "gcp",
    "github",
    "google_workspace",
    "jira",
    "kubernetes",
    "microsoft_365",
    "netsuite",
    "okta",
    "power_platform",
    "salesforce",
    "slack",
    "servicenow",
    "snowflake",
    "stripe",
    "zendesk",
}


def _tool_map(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {tool["id"]: tool for tool in all_tools(evidence) if tool.get("id")}


def _identity_map(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in evidence.get("identity", {}).get("identities", []) if item.get("id")}


def _data_map(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in evidence.get("data_catalog", {}).get("data_sources", []) if item.get("id")}


def _input_map(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in evidence.get("agents", {}).get("input_sources", []) if item.get("id")}


def _events_for(evidence: dict[str, Any], agent_id: str, tool_id: str = "") -> list[dict[str, Any]]:
    events = []
    for event in evidence.get("events", {}).get("events", []):
        if event.get("agent") == agent_id and (not tool_id or event.get("tool") == tool_id):
            events.append(event)
    return events


def _event_score_context(events: list[dict[str, Any]]) -> dict[str, Any]:
    context: dict[str, Any] = {}
    blocked = [event for event in events if event.get("decision") in {"blocked", "deny", "denied"}]
    allowed = [event for event in events if event.get("decision") in {"allow", "allowed"}]
    if allowed:
        context["runtime_observed_allowed"] = f"Runtime event observed allowed action: {allowed[0].get('id')}"
    if blocked:
        context["runtime_observed_blocked"] = f"Runtime event observed blocked attempt: {blocked[0].get('id')}"
        context["blocked_runtime_event"] = f"Blocked runtime event: {blocked[0].get('id')}"
        context["approval_blocks_path"] = True
    return context


def _observation_status(events: list[dict[str, Any]]) -> str:
    if any(event.get("decision") in {"blocked", "deny", "denied"} for event in events):
        return "observed_blocked"
    if any(event.get("decision") in {"allow", "allowed"} for event in events):
        return "observed_allowed"
    return "possible_static"


def _runtime_observation(evidence: dict[str, Any], agent_id: str, sequence_tools: list[str]) -> dict[str, Any]:
    relevant_events = [
        event
        for event in evidence.get("events", {}).get("events", [])
        if event.get("agent") == agent_id and (not sequence_tools or event.get("tool") in sequence_tools)
    ]
    relevant_events = sorted(relevant_events, key=lambda item: (item.get("timestamp", ""), item.get("line", 0)))
    event_ids = [event["id"] for event in relevant_events if event.get("id")]
    session_ids = sorted({event.get("session_id", "") for event in relevant_events if event.get("session_id")})
    last_observed_at = max([event.get("timestamp", "") for event in relevant_events if event.get("timestamp")] or [""])
    blocked = [event for event in relevant_events if event.get("decision") in {"blocked", "deny", "denied"}]
    allowed = [event for event in relevant_events if event.get("decision") in {"allow", "allowed"}]

    full_session = ""
    for session_id in session_ids:
        session_events = [event for event in relevant_events if event.get("session_id") == session_id]
        cursor = 0
        for event in session_events:
            if cursor < len(sequence_tools) and event.get("tool") == sequence_tools[cursor]:
                cursor += 1
        if sequence_tools and cursor == len(sequence_tools):
            full_session = session_id
            break

    if blocked:
        state = "observed_blocked"
        sequence_confidence = "high"
    elif full_session and len(sequence_tools) > 1:
        state = "observed_full"
        sequence_confidence = "high"
    elif allowed and len(sequence_tools) == 1:
        state = "observed_allowed"
        sequence_confidence = "high"
    elif allowed or relevant_events:
        state = "observed_partial"
        sequence_confidence = "medium"
    else:
        state = "not_observed"
        sequence_confidence = "low"

    return {
        "state": state,
        "observed_events": event_ids,
        "session_ids": session_ids,
        "last_observed_at": last_observed_at,
        "sequence_confidence": sequence_confidence,
        "observed_tools": [event.get("tool", "") for event in relevant_events if event.get("tool")],
        "full_sequence_session": full_session,
        "explanation": _runtime_observation_explanation(state, sequence_tools, relevant_events, full_session),
    }


def _runtime_observation_explanation(
    state: str,
    sequence_tools: list[str],
    events: list[dict[str, Any]],
    full_session: str,
) -> str:
    if state == "not_observed":
        return "No runtime events matched this path; classification is based on static evidence."
    if state == "observed_full":
        return f"All path tools were observed in order in session {full_session}."
    if state == "observed_blocked":
        blocked = next((event for event in events if event.get("decision") in {"blocked", "deny", "denied"}), {})
        return f"Runtime event {blocked.get('id')} attempted {blocked.get('tool')} and was blocked."
    if state == "observed_allowed":
        observed = ", ".join(sorted({event.get("tool", "") for event in events if event.get("tool")}))
        expected = ", ".join(sequence_tools)
        return f"Runtime allowed event(s) observed for {observed}; expected path sequence is {expected}."
    return "Some related runtime events were observed, but the full path sequence was not observed."


def _legacy_observation_status(runtime_observation: dict[str, Any]) -> str:
    state = runtime_observation.get("state")
    if state == "observed_blocked":
        return "observed_blocked"
    if state in {"observed_allowed", "observed_full"}:
        return "observed_allowed"
    return "possible_static"


def _path_state(runtime_observation: dict[str, Any], evidence_quality: str) -> str:
    state = runtime_observation.get("state")
    if state in {"observed_blocked", "observed_full", "observed_allowed", "observed_partial"}:
        return state
    if evidence_quality in {"confirmed", "supported"}:
        return "supported"
    if evidence_quality in {"incomplete", "weak"}:
        return "possible"
    return "unknown"


def _untrusted_inputs(agent: dict[str, Any], inputs: dict[str, dict[str, Any]], events: list[dict[str, Any]]) -> list[str]:
    untrusted = [source for source in agent.get("input_sources", []) if inputs.get(source, {}).get("trust") == "untrusted"]
    untrusted.extend(event.get("input_source") for event in events if event.get("input_trust") == "untrusted")
    ordered: list[str] = []
    seen: set[str] = set()
    for item in untrusted:
        if item and item not in seen:
            ordered.append(item)
            seen.add(item)
    return ordered


def _bound_identity_ids(agent: dict[str, Any], tool_id: str) -> list[str]:
    identities: list[str] = []
    for binding in agent.get("tool_identity_bindings", []):
        if isinstance(binding, dict) and binding.get("tool") == tool_id and binding.get("identity"):
            identities.append(str(binding["identity"]))
    return _ordered_unique(identities)


def _ordered_unique(values: list[str]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            ordered.append(value)
            seen.add(value)
    return ordered


def _agent_identity_ids(agent: dict[str, Any]) -> list[str]:
    identities = list(agent.get("identities", []))
    identities.extend(str(binding["identity"]) for binding in agent.get("tool_identity_bindings", []) if isinstance(binding, dict) and binding.get("identity"))
    return _ordered_unique(identities)


def _tool_can_use_identity(
    agent: dict[str, Any],
    tool: dict[str, Any],
    identity_id: str,
    identity: dict[str, Any],
) -> bool:
    tool_id = str(tool.get("id") or "")
    bound = _bound_identity_ids(agent, tool_id)
    if bound:
        return identity_id in bound
    target_system = tool.get("target_system", "unknown")
    return target_system not in {"", "unknown"} and identity.get("target_system") == target_system


def _sensitive_data_for_agent(
    agent: dict[str, Any],
    identities: dict[str, dict[str, Any]],
    data_sources: dict[str, dict[str, Any]],
    tools: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for identity_id in _agent_identity_ids(agent):
        identity = identities.get(identity_id)
        if not identity:
            continue
        for index, permission in enumerate(identity.get("permissions", []), start=1):
            actions = set(permission.get("actions", []))
            permission_classes = set(permission.get("data_classes", []))
            for data_source in data_sources.values():
                classes = set(data_source.get("data_classes", []))
                is_sensitive = (
                    data_source.get("sensitivity") in {"medium", "high", "critical"}
                    or bool(classes.intersection(SENSITIVE_DATA_CLASSES))
                    or bool(permission_classes.intersection(SENSITIVE_DATA_CLASSES))
                )
                permission_matches = (
                    permission.get("resource") == data_source.get("id")
                    or bool(permission_classes.intersection(classes))
                    or identity.get("target_system") == data_source.get("target_system")
                )
                read_tool_id = _read_tool_for_data(agent, tools, data_source, identity_id, identity)
                if is_sensitive and permission_matches and read_tool_id and ("read" in actions or "write" in actions or not actions):
                    key = data_source["id"]
                    if key not in seen:
                        merged = dict(data_source)
                        merged["permission_confidence"] = permission.get("confidence", identity.get("confidence", "medium"))
                        merged["identity"] = identity_id
                        merged["permission_index"] = index
                        merged["permission_resource"] = permission.get("resource", "")
                        merged["permission_actions"] = permission.get("actions", [])
                        results.append(merged)
                        seen.add(key)
    return results


def _tool_identity_permission(
    agent: dict[str, Any],
    identities: dict[str, dict[str, Any]],
    tool: dict[str, Any],
) -> tuple[str, int | None, dict[str, Any] | None]:
    target_system = tool.get("target_system", "")
    bound_identity_ids = _bound_identity_ids(agent, str(tool.get("id") or ""))
    candidate_identity_ids = bound_identity_ids or _agent_identity_ids(agent)
    first_bound_identity = bound_identity_ids[0] if bound_identity_ids else ""
    if not bound_identity_ids and target_system in {"", "unknown"}:
        return "", None, None
    for identity_id in candidate_identity_ids:
        identity = identities.get(identity_id)
        if not identity:
            continue
        if target_system not in {"", "unknown"} and identity.get("target_system") != target_system:
            continue
        permissions = identity.get("permissions", [])
        if not permissions:
            return identity_id, None, None
        for index, permission in enumerate(permissions, start=1):
            actions = set(permission.get("actions", []))
            if actions.intersection({"send", "write", "create", "update", "delete", "use", "read"}):
                return identity_id, index, permission
        return identity_id, 1, permissions[0]
    return first_bound_identity, None, None


def _permission_node(identity_id: str, permission_index: int | None) -> str:
    return node_id("permission", f"{identity_id}:{permission_index}") if identity_id and permission_index else ""


def _read_tool_for_data(
    agent: dict[str, Any],
    tools: dict[str, dict[str, Any]],
    data_source: dict[str, Any],
    identity_id: str = "",
    identity: dict[str, Any] | None = None,
) -> str:
    for tool_id in agent.get("tools", []):
        tool = tools.get(tool_id, {})
        tags = set(tool.get("risk_tags", []))
        if (
            "sensitive_read" in tags
            and tool.get("target_system") == data_source.get("target_system")
            and (not identity_id or _tool_can_use_identity(agent, tool, identity_id, identity or {}))
        ):
            return tool_id
    for tool_id in agent.get("tools", []):
        tool = tools.get(tool_id, {})
        if (
            tool.get("target_system") == data_source.get("target_system")
            and (not identity_id or _tool_can_use_identity(agent, tool, identity_id, identity or {}))
        ):
            return tool_id
    return "" if identity_id and agent.get("tool_identity_bindings") else agent.get("tools", ["unknown"])[0]


def _approval_context(
    evidence: dict[str, Any],
    agent: dict[str, Any],
    tool: dict[str, Any],
    data_classes: list[str] | None = None,
) -> dict[str, Any]:
    return evaluate_policy(
        evidence.get("approval_policy", {}).get("policies", []),
        agent.get("approval_policy", ""),
        {
            "agent": agent.get("id"),
            "tool": tool.get("id"),
            "risk_tags": tool.get("risk_tags", []),
            "action_class": tool.get("risk_tags", [""])[0] if tool.get("risk_tags") else "",
            "target_system": tool.get("target_system", "unknown"),
            "environment": agent.get("environment", "unknown"),
            "data_classes": data_classes or [],
            "external_target": "external" if "external_message" in tool.get("risk_tags", []) else "",
        },
    )


def _approval_score_context(policy_result: dict[str, Any]) -> tuple[dict[str, Any], list[str], list[str]]:
    controls: list[str] = []
    blockers: list[str] = []
    context: dict[str, Any] = {}
    for control in policy_result.get("controls", []):
        control_name = str(control)
        context[control_name] = (
            f"Policy rule {policy_result.get('rule')} declares control {control_name}: "
            f"{policy_result.get('reason') or 'control evidence provided'}"
        )
        controls.append(f"{control_name}:{policy_result.get('rule')}")
    if policy_result.get("decision") == "approval_required":
        context["approval_required"] = f"Approval rule {policy_result.get('rule')} requires review"
        context["approval_blocks_path"] = True
        controls.append(f"approval_required:{policy_result.get('rule')}")
        blockers.append(policy_result.get("reason") or "approval required")
    elif policy_result.get("decision") == "deny":
        context["explicit_deny_policy"] = f"Deny rule {policy_result.get('rule')} blocks action"
        context["approval_blocks_path"] = True
        controls.append(f"deny:{policy_result.get('rule')}")
        blockers.append(policy_result.get("reason") or "denied by policy")
    elif policy_result.get("decision") == "unknown":
        context["missing_approval"] = policy_result.get("reason") or "No matching approval rule found"
    elif policy_result.get("decision") == "allow" and not policy_result.get("controls"):
        controls.append(f"allow:{policy_result.get('rule')}")
    return context, controls, blockers


def _confidence_for_items(*items: dict[str, Any]) -> str:
    confidences = []
    for item in items:
        if item:
            confidences.append(str(item.get("risk_confidence") or item.get("permission_confidence") or item.get("confidence") or "medium"))
    return confidence_max(confidences)


def _agent_metadata_gap_ids(agent: dict[str, Any]) -> list[str]:
    gaps = []
    if not agent.get("owner"):
        gaps.append(f"gap-owner-{agent['id']}")
    if agent.get("environment") in {"", "unknown", None}:
        gaps.append(f"gap-environment-{agent['id']}")
    return gaps


def _operational_context(agent: dict[str, Any], runtime_observation: dict[str, Any]) -> dict[str, Any]:
    labels = agent.get("labels", {}) if isinstance(agent.get("labels"), dict) else {}
    return {
        "agent_id": agent.get("id", ""),
        "agent_name": agent.get("name", ""),
        "owner": agent.get("owner", ""),
        "environment": agent.get("environment", "unknown"),
        "runtime": agent.get("runtime", "unknown"),
        "business_unit": labels.get("business_unit", ""),
        "approval_policy": agent.get("approval_policy", ""),
        "last_observed_at": runtime_observation.get("last_observed_at", ""),
    }


def _has_key_evidence_gap(visibility_gap_ids: list[str]) -> bool:
    return any(
        gap_id.startswith(prefix)
        for gap_id in visibility_gap_ids
        for prefix in ["gap-iam", "gap-tool", "gap-input", "gap-memory", "gap-identity"]
    )


def _evidence_quality(
    *,
    tools: list[dict[str, Any]],
    visibility_gap_ids: list[str],
    runtime_observation: dict[str, Any],
    has_identity_permission: bool,
    has_data_evidence: bool,
    finding_type: str,
) -> str:
    if any(tool.get("risk_source") == "inferred" or tool.get("risk_confidence") == "low" for tool in tools if tool):
        if runtime_observation.get("state") not in {"observed_allowed", "observed_full", "observed_blocked"}:
            return "weak"
    if finding_type == "visibility_gap" or _has_key_evidence_gap(visibility_gap_ids):
        return "incomplete"
    if runtime_observation.get("state") in {"observed_allowed", "observed_full", "observed_blocked"} and (
        has_identity_permission or has_data_evidence
    ):
        return "confirmed"
    if has_identity_permission or has_data_evidence:
        return "supported"
    return "supported"


def _claim_text(
    *,
    evidence_quality: str,
    agent_id: str,
    rule_id: str,
    primary: str,
    target: str,
    approval_missing: bool,
) -> tuple[str, str]:
    approval = " without approval" if approval_missing else " with declared approval control"
    if evidence_quality == "confirmed":
        return (
            f"Confirmed path: {agent_id} can {primary}{approval}.",
            f"Runtime and static evidence support this path to {target}.",
        )
    if evidence_quality == "supported":
        return (
            f"Supported path: {agent_id} has {primary}{approval}.",
            f"Static evidence plus identity or data evidence supports this path to {target}; runtime evidence has not shown the full sequence.",
        )
    if evidence_quality == "weak":
        return (
            f"Possible risk: {agent_id} has tools that resemble {primary}.",
            f"The path to {target} is mostly inferred from tool names, descriptions, or incomplete metadata.",
        )
    return (
        f"Potential path: {agent_id} may {primary}, but key evidence is incomplete.",
        f"The path to {target} needs additional identity, permission, data, runtime, or control evidence before stronger claims are appropriate.",
    )


def _policy_snippet(rule_id: str, data_classes: list[str]) -> dict[str, Any] | None:
    classes = sorted(set(data_classes)) or ["customer_pii"]
    if rule_id == "untrusted_input_to_sensitive_data_to_external_sink":
        return {
            "id": "external-sensitive-data-requires-approval",
            "match": {"action_class": "external_message", "data_classes_any": classes},
            "decision": "approval_required",
            "reason": "External messages containing sensitive data require approval",
        }
    if rule_id == "financial_action_without_approval":
        return {
            "id": "financial-action-requires-approval",
            "match": {"action_class": "financial_action"},
            "decision": "approval_required",
            "reason": "Financial actions require human approval and amount thresholds",
        }
    if rule_id == "production_change_without_approval":
        return {
            "id": "production-write-requires-approval",
            "match": {"action_class": "production_write", "environment": "production"},
            "decision": "approval_required",
            "reason": "Production changes require approval and change-ticket evidence",
        }
    if rule_id in {"dangerous_tool_with_untrusted_input", "mcp_dangerous_tool_exposure"}:
        return {
            "id": "command-execution-requires-sandbox-and-approval",
            "match": {"risk_tag": ["command_execution", "secret_access", "destructive_action"]},
            "decision": "approval_required",
            "controls": ["sandbox_control", "command_allowlist", "secret_denylist"],
            "reason": "Dangerous tool use requires approval and runtime controls",
        }
    if rule_id == "persistent_memory_sensitive_data_gap":
        return {
            "id": "sensitive-memory-requires-retention-policy",
            "match": {"action_class": "memory_write", "data_classes_any": classes},
            "decision": "approval_required",
            "controls": ["dlp_redaction", "audit_logging"],
            "reason": "Sensitive memory writes require retention, redaction, and audit controls",
        }
    return None


def _remediation(
    rule_id: str,
    data_classes: list[str],
    recommended_next_evidence: list[str],
) -> dict[str, Any]:
    common_validation = [
        "Re-run AgentGuard Graph after adding the requested evidence or policy changes.",
        "Confirm runtime logs include agent, tool, decision, session_id, and timestamp fields.",
    ]
    controls_by_rule = {
        "untrusted_input_to_sensitive_data_to_external_sink": [
            "Require approval for external messages containing sensitive data.",
            "Split sensitive-data read capability from external-send capability.",
            "Reduce target-system permissions to the minimum required objects or fields.",
            "Add runtime logging for all external message attempts.",
            "Add redaction or DLP before outbound send.",
        ],
        "financial_action_without_approval": [
            "Require human approval for financial actions.",
            "Add amount thresholds and dual-control review.",
            "Use a scoped identity for payment creation.",
            "Record immutable audit events for each attempted transaction.",
        ],
        "production_change_without_approval": [
            "Require approval and change-ticket evidence for production writes.",
            "Split plan/read actions from apply/write actions.",
            "Use separate production identities with least privilege.",
            "Add deployment-window or environment allowlist controls.",
        ],
        "dangerous_tool_with_untrusted_input": [
            "Sandbox tool execution.",
            "Require approval for command execution or destructive operations.",
            "Add command allowlists and secret deny lists.",
            "Separate low-privilege analysis agents from high-privilege execution agents.",
        ],
        "mcp_dangerous_tool_exposure": [
            "Restrict dangerous MCP tool visibility.",
            "Require approval for dangerous MCP tools.",
            "Review and pin MCP descriptors.",
            "Record descriptor source and runtime calls.",
        ],
        "persistent_memory_sensitive_data_gap": [
            "Add retention and deletion policy for sensitive memory.",
            "Redact sensitive fields before memory write.",
            "Classify memory store contents.",
            "Log memory writes with data classes.",
        ],
        "unknown_target_iam_gap": [
            "Provide target-system permission export.",
            "Provide OAuth scope or service account policy export.",
            "Map permissions to reachable data classes.",
            "Re-run the scan with identity evidence.",
        ],
    }
    validation_by_rule = {
        "untrusted_input_to_sensitive_data_to_external_sink": [
            "Confirm whether external send is restricted to internal recipients.",
            "Confirm whether sensitive fields are redacted before outbound send.",
        ],
        "financial_action_without_approval": ["Confirm amount thresholds and approval workflow are enforced."],
        "production_change_without_approval": ["Confirm write tools require a valid change ticket."],
        "dangerous_tool_with_untrusted_input": ["Generate runtime events for allowed and blocked command attempts."],
        "mcp_dangerous_tool_exposure": ["Confirm descriptor review and visibility policy for dangerous MCP tools."],
        "persistent_memory_sensitive_data_gap": ["Confirm deletion workflow and retention policy are applied to the memory store."],
        "unknown_target_iam_gap": ["Re-run with the missing permission export and confirm the gap is resolved."],
    }
    return {
        "recommended_controls": controls_by_rule.get(rule_id, ["Add explicit approval, identity, and runtime evidence."]),
        "policy_snippet": _policy_snippet(rule_id, data_classes),
        "least_privilege_recommendation": "Remove unused scopes, split read/write identities, and scope access to the minimum data classes required.",
        "required_next_evidence": recommended_next_evidence,
        "validation_steps": validation_by_rule.get(rule_id, []) + common_validation,
    }


def _apply_evidence_quality_caps(score: ScoreResult, evidence_quality: str) -> ScoreResult:
    cap = None
    reason = ""
    if evidence_quality == "weak":
        cap = 39
        reason = "weak evidence is capped below medium"
    elif evidence_quality == "incomplete":
        cap = 64
        reason = "incomplete evidence is capped below high"
    if cap is not None and score.score > cap:
        score.score = cap
        score.tier = tier_for_score(score.score)
        if reason not in score.caps:
            score.caps.append(reason)
    if score.score > 100:
        score.score = 100
        score.tier = tier_for_score(score.score)
        if "public score capped at 100" not in score.caps:
            score.caps.append("public score capped at 100")
    return score


def _prioritize_visibility_gaps(
    gaps: list[VisibilityGap],
    findings: list[Finding],
    paths: list[AttackPath],
) -> list[VisibilityGap]:
    finding_by_gap: dict[str, list[Finding]] = {}
    for finding in findings:
        for gap_id in finding.visibility_gaps:
            finding_by_gap.setdefault(gap_id, []).append(finding)
    for gap in gaps:
        affected = finding_by_gap.get(gap.id, [])
        gap.affected_findings = sorted(finding.id for finding in affected)
        highest = max([finding.score for finding in affected] or [0])
        if gap.type in {"unknown_target_iam_gap", "target_system_permissions_unknown", "tool_evidence_unknown"} and highest >= 65:
            gap.priority = "critical_gap"
        elif gap.type in {
            "unknown_target_iam_gap",
            "target_system_permissions_unknown",
            "identity_unknown",
            "approval_policy_gap",
            "offline_tool_control_gap",
            "generic_tool_surface_gap",
            "system_prompt_security_boundary_gap",
            "data_catalog_empty",
            "memory_retention_policy_gap",
        }:
            gap.priority = "high_gap"
        elif gap.type in {"environment_unknown", "owner_metadata_missing"}:
            gap.priority = "medium_gap" if gap.type == "environment_unknown" else "low_gap"
        else:
            gap.priority = "medium_gap" if gap.severity in {"medium", "high"} else "low_gap"
    priority_by_gap = {gap.id: gap.priority for gap in gaps}
    for finding in findings:
        finding.visibility_gap_priorities = sorted(
            {priority_by_gap[gap_id] for gap_id in finding.visibility_gaps if gap_id in priority_by_gap}
        )
    for path in paths:
        path.visibility_gap_priorities = sorted(
            {priority_by_gap[gap_id] for gap_id in path.visibility_gaps if gap_id in priority_by_gap}
        )
    priority_order = {"critical_gap": 0, "high_gap": 1, "medium_gap": 2, "low_gap": 3}
    return sorted(gaps, key=lambda gap: (priority_order.get(gap.priority, 9), gap.id))


def _stable_id(prefix: str, rule_id: str, nodes: list[str], evidence_summary: list[str]) -> str:
    payload = json.dumps(
        {"rule_id": rule_id, "nodes": nodes, "evidence_summary": evidence_summary},
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"{prefix}-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:12]}"


def _policy_node(agent: dict[str, Any]) -> str:
    return node_id("approval_policy", agent.get("approval_policy") or "unknown")


def _approval_edge_id(agent: dict[str, Any], tool_id: str, missing: bool) -> str:
    return edge_id("approval_missing" if missing else "approval_present", node_id("tool", tool_id), _policy_node(agent))


def _tool_data_edge_id(tool_id: str, data_source_id: str, edge_type: str = "tool_reads_data") -> str:
    return edge_id(edge_type, node_id("tool", tool_id), node_id("data_source", data_source_id))


def _finding_from_path(
    path: AttackPath,
    description: str,
    evidence: list[str],
    controls: list[str],
    source_files_list: list[str],
    finding_type: str = "attack_path",
) -> Finding:
    return Finding(
        id=path.id.replace("path-", "finding-", 1),
        title=path.title,
        description=description,
        tier=path.tier,
        score=path.score,
        confidence=path.confidence,
        path=path.evidence_summary,
        nodes=path.nodes,
        edges=path.edges,
        evidence=evidence,
        unknowns=path.unknowns,
        blockers=path.blockers,
        controls=controls,
        recommendations=path.recommendations,
        source_files=source_files_list,
        related_events=path.related_events,
        evidence_layer=path.evidence_layer,
        observation_status=path.observation_status,
        path_state=path.path_state,
        evidence_quality=path.evidence_quality,
        runtime_observation=path.runtime_observation,
        remediation=path.remediation,
        operational_context=path.operational_context,
        visibility_gaps=path.visibility_gaps,
        visibility_gap_priorities=path.visibility_gap_priorities,
        recommended_next_evidence=path.recommended_next_evidence,
        scoring=path.scoring,
        finding_type=finding_type,
        rule_id=path.rule_id,
    )


def _offline_score_context(row: dict[str, Any]) -> dict[str, Any]:
    tags = set(row.get("risk_tags", []))
    context: dict[str, Any] = {
        "has_sensitive_or_critical_action": bool(tags.intersection(DANGEROUS_TAGS | {"external_message", "financial_action", "network_access", "memory_write"})),
        "confidences": [row.get("risk_confidence", "medium")],
    }
    if "command_execution" in tags:
        context["command_execution"] = f"{row.get('tool')} can execute commands"
    if "secret_access" in tags:
        context["secret_access"] = f"{row.get('tool')} can access secret-like material"
    if tags.intersection({"external_message", "data_exfiltration_sink", "network_access"}):
        context["external_sink"] = f"{row.get('tool')} can send data outside or reach the network"
    if tags.intersection({"production_write", "infrastructure_write", "ci_cd_write", "repository_write", "destructive_action"}):
        context["production_write"] = f"{row.get('tool')} can modify production-like systems"
    if "financial_action" in tags:
        context["financial_action"] = f"{row.get('tool')} can perform financial actions"
    if "approval_required" in row.get("missing_required_controls", []):
        context["missing_approval"] = "Offline policy evidence does not require approval or deny this action"
    for control in row.get("declared_controls", []):
        if control in {
            "approval_required",
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
        }:
            context[control] = f"Offline policy evidence declares {control_label(control)}"
        if control == "explicit_deny_policy":
            context["explicit_deny_policy"] = "Offline policy evidence denies this action"
    return context


def _offline_finding_id(rule_id: str, nodes: list[str], evidence_summary: list[str]) -> str:
    return _stable_id("finding", rule_id, nodes, evidence_summary)


def _offline_remediation(row: dict[str, Any]) -> dict[str, Any]:
    missing = row.get("missing_required_controls", [])
    required_evidence = [
        f"Add offline policy evidence for {row.get('tool')}: {control_label(control)}."
        for control in missing
    ]
    return {
        "recommended_controls": [control_label(control) for control in missing]
        or ["Keep every high-risk tool covered by explicit local policy evidence."],
        "policy_snippet": {
            "id": f"{str(row.get('tool', 'tool')).replace('.', '-')}-offline-controls",
            "match": {"tool": row.get("tool", "")},
            "decision": "approval_required",
            "controls": [control for control in missing if control != "approval_required"],
            "reason": "High-risk AI tool use requires offline-reviewed controls.",
        }
        if missing
        else None,
        "least_privilege_recommendation": "Prefer narrow typed tools, scoped identities, and explicit target-system permissions.",
        "required_next_evidence": required_evidence,
        "validation_steps": [
            "Re-run AgentGuard Graph after adding local policy evidence.",
            "Confirm the generated policy rule uses only schema-supported match keys and control tags.",
        ],
    }


def analyze_attack_paths(evidence: dict[str, Any], visibility_gaps: list[VisibilityGap] | None = None) -> tuple[list[AttackPath], list[Finding], list[VisibilityGap]]:
    tools = _tool_map(evidence)
    identities = _identity_map(evidence)
    data_sources = _data_map(evidence)
    inputs = _input_map(evidence)
    source_files_list = source_files(evidence)
    gaps = list(visibility_gaps or [])
    paths: list[AttackPath] = []
    findings: list[Finding] = []

    def add_path(
        *,
        rule_id: str,
        title: str,
        nodes: list[str],
        edges: list[str],
        evidence_summary: list[str],
        evidence_lines: list[str],
        unknowns: list[str],
        blockers: list[str],
        controls: list[str] | None = None,
        visibility_gap_ids: list[str] | None = None,
        recommended_next_evidence: list[str] | None = None,
        recommendations: list[str],
        score: ScoreResult,
        confidence: str,
        related_events: list[str] | None = None,
        observation_status: str = "possible_static",
        runtime_observation: dict[str, Any] | None = None,
        evidence_quality: str = "incomplete",
        remediation: dict[str, Any] | None = None,
        operational_context: dict[str, Any] | None = None,
        description: str,
        finding_type: str = "attack_path",
    ) -> None:
        nodes = [item for item in dict.fromkeys(nodes) if item]
        edges = [item for item in dict.fromkeys(edges) if item]
        visibility_gap_ids = list(dict.fromkeys(visibility_gap_ids or []))
        recommended_next_evidence = list(dict.fromkeys(recommended_next_evidence or []))
        runtime_observation = runtime_observation or {"state": "not_observed", "observed_events": [], "session_ids": [], "last_observed_at": "", "sequence_confidence": "low"}
        score = _apply_evidence_quality_caps(score, evidence_quality)
        path_id = _stable_id("path", rule_id, nodes, evidence_summary)
        path = AttackPath(
            id=path_id,
            rule_id=rule_id,
            title=title,
            nodes=nodes,
            edges=edges,
            evidence_summary=evidence_summary,
            unknowns=unknowns,
            blockers=blockers,
            score=score.score,
            tier=score.tier,
            recommendations=recommendations,
            confidence=confidence,
            observation_status=observation_status,
            path_state=_path_state(runtime_observation, evidence_quality),
            evidence_quality=evidence_quality,
            runtime_observation=runtime_observation,
            remediation=remediation or {},
            operational_context=operational_context or {},
            visibility_gaps=visibility_gap_ids,
            recommended_next_evidence=recommended_next_evidence,
            scoring=score,
            related_events=related_events or [],
        )
        paths.append(path)
        findings.append(_finding_from_path(path, description, evidence_lines, controls or [], source_files_list, finding_type))

    for agent in evidence.get("agents", {}).get("agents", []):
        agent_events = _events_for(evidence, agent["id"])
        untrusted = _untrusted_inputs(agent, inputs, agent_events)
        sensitive_data = _sensitive_data_for_agent(agent, identities, data_sources, tools)
        external_tools = [
            tools[tool_id]
            for tool_id in agent.get("tools", [])
            if tool_id in tools and set(tools[tool_id].get("risk_tags", [])).intersection({"external_message", "data_exfiltration_sink"})
        ]
        if untrusted and sensitive_data and external_tools:
            data_source = sorted(sensitive_data, key=lambda item: {"critical": 0, "high": 1, "medium": 2}.get(item.get("sensitivity"), 3))[0]
            external_tool = external_tools[0]
            read_tool_id = _read_tool_for_data(agent, tools, data_source)
            read_tool = tools.get(read_tool_id, {})
            policy_result = _approval_context(evidence, agent, external_tool, data_source.get("data_classes", []))
            policy_context, controls, blockers = _approval_score_context(policy_result)
            sequence_tools = [read_tool_id, external_tool["id"]]
            runtime = _runtime_observation(evidence, agent["id"], sequence_tools)
            events = [event for event in agent_events if event.get("id") in set(runtime.get("observed_events", []))]
            event_context = _event_score_context(events)
            sensitivity = data_source.get("sensitivity", "unknown")
            score_context = {
                "untrusted_input": f"Agent receives untrusted input: {', '.join(untrusted)}",
                "external_sink": f"Tool {external_tool['id']} can send externally",
                "autonomous_agent": f"Agent autonomy is {agent.get('autonomy')}" if agent.get("autonomy") == "autonomous" else "",
                "approval_required_agent": (
                    f"Agent autonomy is {agent.get('autonomy')}" if agent.get("autonomy") == "approval_required" else ""
                ),
                "has_sensitive_or_critical_action": True,
                "confidences": [
                    read_tool.get("risk_confidence", "medium"),
                    external_tool.get("risk_confidence", "medium"),
                    data_source.get("permission_confidence", "medium"),
                ],
            }
            if sensitivity == "critical":
                score_context["sensitive_data_critical"] = f"{data_source['id']} is critical"
                score_context["critical_blocked_attempt"] = bool(event_context.get("blocked_runtime_event"))
            elif sensitivity == "high":
                score_context["sensitive_data_high"] = f"{data_source['id']} is high sensitivity"
            else:
                score_context["sensitive_data_medium"] = f"{data_source['id']} is medium or inferred sensitive"
            score_context.update(policy_context)
            score_context.update(event_context)
            score = score_path(score_context)
            input_node = node_id("input_source", untrusted[0])
            agent_node = node_id("agent", agent["id"])
            read_tool_node = node_id("tool", read_tool_id)
            data_node = node_id("data_source", data_source["id"])
            external_tool_node = node_id("tool", external_tool["id"])
            sink_node = node_id("external_sink", f"{external_tool['id']}:external")
            approval_missing = policy_result.get("decision") == "unknown"
            read_identity_id = str(data_source.get("identity", ""))
            read_identity_node = node_id("identity", read_identity_id) if read_identity_id else ""
            read_permission_node = _permission_node(read_identity_id, data_source.get("permission_index"))
            external_identity_id, external_permission_index, _external_permission = _tool_identity_permission(
                agent, identities, external_tool
            )
            external_identity_node = node_id("identity", external_identity_id) if external_identity_id else ""
            external_permission_node = _permission_node(external_identity_id, external_permission_index)
            external_iam_gap = (
                [f"gap-iam-{agent['id']}-{external_tool.get('target_system')}"]
                if external_tool.get("target_system") in IAM_VISIBILITY_TARGET_SYSTEMS
                and not external_permission_node
                else []
            )
            visibility_ids = (
                ([f"gap-approval-{agent['id']}-{external_tool['id']}"] if approval_missing else [])
                + external_iam_gap
                + _agent_metadata_gap_ids(agent)
            )
            evidence_quality = _evidence_quality(
                tools=[read_tool, external_tool],
                visibility_gap_ids=visibility_ids,
                runtime_observation=runtime,
                has_identity_permission=bool(read_permission_node and external_permission_node),
                has_data_evidence=True,
                finding_type="attack_path",
            )
            title, description = _claim_text(
                evidence_quality=evidence_quality,
                agent_id=agent["id"],
                rule_id="untrusted_input_to_sensitive_data_to_external_sink",
                primary=f"read {data_source['id']} and send externally",
                target="external recipient",
                approval_missing=approval_missing,
            )
            required_next = (
                ["Add approval policy evidence for outbound sensitive-data actions."]
                if approval_missing
                else ["Provide runtime external-send events to distinguish observed from possible behavior."]
            )
            required_next.extend(gap.requested_evidence for gap in gaps if gap.id in external_iam_gap)
            add_path(
                rule_id="untrusted_input_to_sensitive_data_to_external_sink",
                title=title,
                nodes=[
                    input_node,
                    agent_node,
                    read_identity_node,
                    read_permission_node,
                    read_tool_node,
                    data_node,
                    external_identity_node,
                    external_permission_node,
                    external_tool_node,
                    sink_node,
                ],
                edges=[
                    edge_id("agent_receives_input", input_node, agent_node),
                    edge_id("agent_runs_as_identity", agent_node, read_identity_node) if read_identity_node else "",
                    edge_id("identity_has_permission", read_identity_node, read_permission_node) if read_permission_node else "",
                    edge_id("permission_reaches_data", read_permission_node, data_node) if read_permission_node else "",
                    edge_id("agent_uses_tool", agent_node, read_tool_node),
                    _tool_data_edge_id(read_tool_id, data_source["id"]),
                    edge_id("agent_runs_as_identity", agent_node, external_identity_node) if external_identity_node else "",
                    edge_id("identity_has_permission", external_identity_node, external_permission_node)
                    if external_permission_node
                    else "",
                    edge_id("agent_uses_tool", agent_node, external_tool_node),
                    edge_id("tool_sends_external", external_tool_node, sink_node),
                    _approval_edge_id(agent, external_tool["id"], approval_missing),
                ],
                evidence_summary=[
                    untrusted[0],
                    agent["id"],
                    read_identity_id or "identity unknown",
                    f"{data_source.get('permission_resource', data_source['id'])}.{','.join(data_source.get('permission_actions', []))}"
                    if data_source.get("permission_resource")
                    else "permission unknown",
                    read_tool_id,
                    data_source["id"],
                    external_identity_id or "external-send identity unknown",
                    external_tool["id"],
                    "external recipient",
                ],
                evidence_lines=[
                    f"{agent.get('source_file')}: {agent['id']} receives {', '.join(untrusted)}",
                    f"{data_source.get('source_file')}: {data_source['id']} contains {', '.join(data_source.get('data_classes', []))}",
                    f"{external_tool.get('source_file')}: {external_tool['id']} has risk tags {', '.join(external_tool.get('risk_tags', []))}",
                    f"{policy_result.get('source_file') or 'approval-policy'}: {policy_result.get('reason')}",
                ],
                unknowns=[
                    "Runtime external-send behavior was not observed unless related events are present.",
                    "Target-system permissions are only as accurate as provided identity evidence.",
                ]
                if not events
                else ["Future behavior can differ from observed runtime events."],
                blockers=blockers,
                controls=controls,
                visibility_gap_ids=visibility_ids,
                recommended_next_evidence=required_next,
                recommendations=[
                    "require approval for outbound messages containing sensitive data",
                    "split read and send capabilities",
                    "reduce target-system permissions",
                    "add DLP or redaction",
                    "add runtime logging",
                ],
                score=score,
                confidence=_confidence_for_items(read_tool, external_tool, data_source),
                related_events=runtime.get("observed_events", []),
                observation_status=_legacy_observation_status(runtime),
                runtime_observation=runtime,
                evidence_quality=evidence_quality,
                remediation=_remediation(
                    "untrusted_input_to_sensitive_data_to_external_sink",
                    data_source.get("data_classes", []),
                    required_next,
                ),
                operational_context=_operational_context(agent, runtime),
                description=description,
            )

        for tool_id in agent.get("tools", []):
            tool = tools.get(tool_id)
            if not tool:
                continue
            risk_tags = set(tool.get("risk_tags", []))
            if untrusted and risk_tags.intersection(DANGEROUS_TAGS):
                policy_result = _approval_context(evidence, agent, tool)
                policy_context, controls, blockers = _approval_score_context(policy_result)
                events = _events_for(evidence, agent["id"], tool_id)
                score_context = {
                    "untrusted_input": f"Agent receives untrusted input: {', '.join(untrusted)}",
                    "mcp_dangerous_tool": f"MCP/static evidence exposes dangerous tool {tool_id}",
                    "autonomous_agent": f"Agent autonomy is {agent.get('autonomy')}" if agent.get("autonomy") == "autonomous" else "",
                    "has_sensitive_or_critical_action": True,
                    "confidences": [tool.get("risk_confidence", "medium")],
                }
                if "command_execution" in risk_tags:
                    score_context["command_execution"] = f"{tool_id} has command_execution risk"
                if "secret_access" in risk_tags:
                    score_context["secret_access"] = f"{tool_id} has secret_access risk"
                if risk_tags.intersection({"production_write", "infrastructure_write", "ci_cd_write", "repository_write"}):
                    score_context["production_write"] = f"{tool_id} can modify production-like or repository systems"
                score_context.update(policy_context)
                score_context.update(_event_score_context(events))
                score = score_path(score_context)
                input_node = node_id("input_source", untrusted[0])
                agent_node = node_id("agent", agent["id"])
                tool_node = node_id("tool", tool_id)
                command_node = node_id("unknown", f"{tool_id}:command_execution")
                production_node = node_id("unknown", f"{tool_id}:production_change")
                data_targets = [
                    data_source
                    for data_source in data_sources.values()
                    if data_source.get("target_system") == tool.get("target_system")
                ]
                if "secret_access" in risk_tags and "secret_path_unknown" in data_sources:
                    target = "secret-like paths"
                    target_node = node_id("data_source", "secret_path_unknown")
                    target_edge = _tool_data_edge_id(tool_id, "secret_path_unknown")
                elif risk_tags.intersection({"filesystem_write", "repository_write", "code_write"}) and data_targets:
                    target = data_targets[0]["id"]
                    target_node = node_id("data_source", data_targets[0]["id"])
                    target_edge = _tool_data_edge_id(tool_id, data_targets[0]["id"], "tool_writes_data")
                elif "command_execution" in risk_tags:
                    target = "command execution"
                    target_node = command_node
                    target_edge = edge_id("tool_executes_command", tool_node, command_node)
                else:
                    target = f"{tool.get('target_system', 'production')} production surface"
                    target_node = production_node
                    target_edge = edge_id("tool_modifies_production", tool_node, production_node)
                danger_edges = [
                    edge_id("agent_receives_input", input_node, agent_node),
                    edge_id("agent_uses_tool", agent_node, tool_node),
                    target_edge,
                    _approval_edge_id(agent, tool_id, policy_result.get("decision") == "unknown"),
                ]
                if "command_execution" in risk_tags and target_edge != edge_id("tool_executes_command", tool_node, command_node):
                    danger_edges.insert(2, edge_id("tool_executes_command", tool_node, command_node))
                runtime = _runtime_observation(evidence, agent["id"], [tool_id])
                visibility_ids = (
                    [f"gap-approval-{agent['id']}-{tool_id}"] if policy_result.get("decision") == "unknown" else []
                ) + _agent_metadata_gap_ids(agent)
                evidence_quality = _evidence_quality(
                    tools=[tool],
                    visibility_gap_ids=visibility_ids,
                    runtime_observation=runtime,
                    has_identity_permission=False,
                    has_data_evidence=bool(data_targets),
                    finding_type="attack_path",
                )
                title, description = _claim_text(
                    evidence_quality=evidence_quality,
                    agent_id=agent["id"],
                    rule_id="dangerous_tool_with_untrusted_input",
                    primary=f"use {tool_id} for {target} with untrusted input",
                    target=target,
                    approval_missing=policy_result.get("decision") == "unknown",
                )
                add_path(
                    rule_id="dangerous_tool_with_untrusted_input",
                    title=title,
                    nodes=[input_node, agent_node, tool_node, target_node],
                    edges=danger_edges,
                    evidence_summary=[untrusted[0], agent["id"], tool_id, target],
                    evidence_lines=[
                        f"{agent.get('source_file')}: {agent['id']} receives {', '.join(untrusted)}",
                        f"{tool.get('source_file')}: {tool_id} has risk tags {', '.join(tool.get('risk_tags', []))}",
                        f"{policy_result.get('source_file') or 'approval-policy'}: {policy_result.get('reason')}",
                    ],
                    unknowns=["Sandbox, allowlist, and secret denylist controls are missing unless declared in policy evidence."],
                    blockers=blockers,
                    controls=controls,
                    visibility_gap_ids=visibility_ids,
                    recommended_next_evidence=[
                        "Provide sandbox, allowlist, approval, and runtime event evidence for dangerous tool use."
                    ],
                    recommendations=[
                        "sandbox tool",
                        "require approval",
                        "deny secret paths",
                        "restrict command allowlist",
                        "separate low and high privilege agents",
                    ],
                    score=score,
                    confidence=tool.get("risk_confidence", "medium"),
                    related_events=runtime.get("observed_events", []),
                    observation_status=_legacy_observation_status(runtime),
                    runtime_observation=runtime,
                    evidence_quality=evidence_quality,
                    remediation=_remediation(
                        "dangerous_tool_with_untrusted_input",
                        [],
                        ["Provide sandbox, allowlist, approval, and runtime event evidence for dangerous tool use."],
                    ),
                    operational_context=_operational_context(agent, runtime),
                    description=description,
                )
                if tool.get("server_id"):
                    server_node = node_id("mcp_server", tool.get("server_id"))
                    mcp_title, mcp_description = _claim_text(
                        evidence_quality=evidence_quality,
                        agent_id=agent["id"],
                        rule_id="mcp_dangerous_tool_exposure",
                        primary=f"reach dangerous MCP tool {tool_id}",
                        target=target,
                        approval_missing=policy_result.get("decision") == "unknown",
                    )
                    add_path(
                        rule_id="mcp_dangerous_tool_exposure",
                        title=mcp_title,
                        nodes=[
                            input_node,
                            agent_node,
                            server_node,
                            tool_node,
                            target_node,
                        ],
                        edges=[
                            edge_id("agent_receives_input", input_node, agent_node),
                            edge_id("tool_defined_by_mcp_server", server_node, tool_node),
                            edge_id("agent_uses_tool", agent_node, tool_node),
                            *([edge_id("tool_executes_command", tool_node, command_node)] if "command_execution" in risk_tags else []),
                            target_edge,
                            _approval_edge_id(agent, tool_id, policy_result.get("decision") == "unknown"),
                        ],
                        evidence_summary=[untrusted[0], agent["id"], tool.get("server_id"), tool_id, target],
                        evidence_lines=[
                            f"{tool.get('source_file')}: MCP server {tool.get('server_id')} exposes {tool_id}",
                            f"{tool.get('source_file')}: {tool_id} has risk tags {', '.join(tool.get('risk_tags', []))}",
                            f"{policy_result.get('source_file') or 'approval-policy'}: {policy_result.get('reason')}",
                        ],
                        unknowns=["Tool descriptor integrity, sandboxing, and descriptor review evidence were not provided."],
                        blockers=blockers,
                        controls=controls,
                        visibility_gap_ids=visibility_ids,
                        recommended_next_evidence=[
                            "Provide descriptor hash/signature, tool visibility policy, sandbox evidence, and runtime events."
                        ],
                        recommendations=[
                            "restrict tool visibility",
                            "require approval",
                            "sign or verify tool descriptors later",
                            "record descriptor hash",
                            "review tool description for hidden instructions",
                        ],
                        score=score,
                        confidence=tool.get("risk_confidence", "medium"),
                        related_events=runtime.get("observed_events", []),
                        observation_status=_legacy_observation_status(runtime),
                        runtime_observation=runtime,
                        evidence_quality=evidence_quality,
                        remediation=_remediation(
                            "mcp_dangerous_tool_exposure",
                            [],
                            [
                                "Provide descriptor hash/signature, tool visibility policy, sandbox evidence, and runtime events."
                            ],
                        ),
                        operational_context=_operational_context(agent, runtime),
                        description=mcp_description,
                    )

            if "financial_action" in risk_tags:
                policy_result = _approval_context(evidence, agent, tool)
                policy_context, controls, blockers = _approval_score_context(policy_result)
                score_context = {
                    "financial_action": f"{tool_id} has financial_action risk",
                    "autonomous_agent": f"Agent autonomy is {agent.get('autonomy')}" if agent.get("autonomy") == "autonomous" else "",
                    "untrusted_input": f"Agent receives untrusted input: {', '.join(untrusted)}" if untrusted else "",
                    "has_sensitive_or_critical_action": True,
                    "confidences": [tool.get("risk_confidence", "medium")],
                }
                score_context.update(policy_context)
                events = _events_for(evidence, agent["id"], tool_id)
                score_context.update(_event_score_context(events))
                score = score_path(score_context)
                runtime = _runtime_observation(evidence, agent["id"], [tool_id])
                agent_node = node_id("agent", agent["id"])
                tool_node = node_id("tool", tool_id)
                financial_node = node_id("unknown", f"{tool_id}:financial_action")
                approval_missing = policy_result.get("decision") == "unknown"
                identity_id, permission_index, permission = _tool_identity_permission(agent, identities, tool)
                identity_node = node_id("identity", identity_id) if identity_id else ""
                permission_node = _permission_node(identity_id, permission_index)
                visibility_ids = ([f"gap-approval-{agent['id']}-{tool_id}"] if approval_missing else []) + _agent_metadata_gap_ids(agent)
                evidence_quality = _evidence_quality(
                    tools=[tool],
                    visibility_gap_ids=visibility_ids,
                    runtime_observation=runtime,
                    has_identity_permission=bool(permission),
                    has_data_evidence=bool(permission and permission.get("data_classes")),
                    finding_type="attack_path",
                )
                title, description = _claim_text(
                    evidence_quality=evidence_quality,
                    agent_id=agent["id"],
                    rule_id="financial_action_without_approval",
                    primary=f"use {tool_id} for financial action",
                    target="financial action",
                    approval_missing=approval_missing,
                )
                add_path(
                    rule_id="financial_action_without_approval",
                    title=title,
                    nodes=[agent_node, identity_node, permission_node, tool_node, financial_node],
                    edges=[
                        edge_id("agent_runs_as_identity", agent_node, identity_node) if identity_node else "",
                        edge_id("identity_has_permission", identity_node, permission_node) if permission_node else "",
                        edge_id("agent_uses_tool", agent_node, tool_node),
                        edge_id("tool_writes_data", tool_node, financial_node),
                        _approval_edge_id(agent, tool_id, approval_missing),
                    ],
                    evidence_summary=([untrusted[0]] if untrusted else []) + [agent["id"], tool_id, "financial_action"],
                    evidence_lines=[
                        f"{tool.get('source_file')}: {tool_id} has financial_action risk",
                        f"{policy_result.get('source_file') or 'approval-policy'}: {policy_result.get('reason')}",
                    ],
                    unknowns=["Transaction thresholds and runtime approval behavior were not provided."],
                    blockers=blockers,
                    controls=controls,
                    visibility_gap_ids=visibility_ids,
                    recommended_next_evidence=[
                        "Provide financial approval policy, amount thresholds, scoped identity, and audit events."
                    ],
                    recommendations=["require human approval", "add amount threshold", "add audit logging", "use scoped identity"],
                    score=score,
                    confidence=tool.get("risk_confidence", "medium"),
                    related_events=runtime.get("observed_events", []),
                    observation_status=_legacy_observation_status(runtime),
                    runtime_observation=runtime,
                    evidence_quality=evidence_quality,
                    remediation=_remediation(
                        "financial_action_without_approval",
                        permission.get("data_classes", []) if permission else [],
                        ["Provide financial approval policy, amount thresholds, scoped identity, and audit events."],
                    ),
                    operational_context=_operational_context(agent, runtime),
                    description=description,
                )

            if (
                agent.get("environment") == "production"
                and risk_tags.intersection({"production_write", "infrastructure_write", "ci_cd_write", "repository_write"})
            ):
                policy_result = _approval_context(evidence, agent, tool)
                policy_context, controls, blockers = _approval_score_context(policy_result)
                score_context = {
                    "production_write": f"{tool_id} can write to production-like systems",
                    "autonomous_agent": f"Agent autonomy is {agent.get('autonomy')}" if agent.get("autonomy") == "autonomous" else "",
                    "has_sensitive_or_critical_action": True,
                    "confidences": [tool.get("risk_confidence", "medium")],
                }
                score_context.update(policy_context)
                events = _events_for(evidence, agent["id"], tool_id)
                score_context.update(_event_score_context(events))
                score = score_path(score_context)
                runtime = _runtime_observation(evidence, agent["id"], [tool_id])
                agent_node = node_id("agent", agent["id"])
                tool_node = node_id("tool", tool_id)
                production_node = node_id("unknown", f"{tool_id}:production_change")
                approval_missing = policy_result.get("decision") == "unknown"
                identity_id, permission_index, permission = _tool_identity_permission(agent, identities, tool)
                identity_node = node_id("identity", identity_id) if identity_id else ""
                permission_node = _permission_node(identity_id, permission_index)
                visibility_ids = ([f"gap-approval-{agent['id']}-{tool_id}"] if approval_missing else []) + _agent_metadata_gap_ids(agent)
                evidence_quality = _evidence_quality(
                    tools=[tool],
                    visibility_gap_ids=visibility_ids,
                    runtime_observation=runtime,
                    has_identity_permission=bool(permission),
                    has_data_evidence=bool(permission and permission.get("data_classes")),
                    finding_type="attack_path",
                )
                title, description = _claim_text(
                    evidence_quality=evidence_quality,
                    agent_id=agent["id"],
                    rule_id="production_change_without_approval",
                    primary=f"use {tool_id} to modify production-like systems",
                    target="production write surface",
                    approval_missing=approval_missing,
                )
                add_path(
                    rule_id="production_change_without_approval",
                    title=title,
                    nodes=[agent_node, identity_node, permission_node, tool_node, production_node],
                    edges=[
                        edge_id("agent_runs_as_identity", agent_node, identity_node) if identity_node else "",
                        edge_id("identity_has_permission", identity_node, permission_node) if permission_node else "",
                        edge_id("agent_uses_tool", agent_node, tool_node),
                        edge_id("tool_modifies_production", tool_node, production_node),
                        _approval_edge_id(agent, tool_id, approval_missing),
                    ],
                    evidence_summary=[agent["id"], tool_id, "production write"],
                    evidence_lines=[f"{tool.get('source_file')}: {tool_id} has production/repository write risk"],
                    unknowns=["Change-ticket and production identity controls were not declared."],
                    blockers=blockers,
                    controls=controls,
                    visibility_gap_ids=visibility_ids,
                    recommended_next_evidence=[
                        "Provide change-ticket policy, approval policy, production identity export, and runtime write events."
                    ],
                    recommendations=[
                        "allow plan/read actions only",
                        "require approval for apply/write",
                        "separate production identity",
                        "add change-ticket requirement",
                    ],
                    score=score,
                    confidence=tool.get("risk_confidence", "medium"),
                    related_events=runtime.get("observed_events", []),
                    observation_status=_legacy_observation_status(runtime),
                    runtime_observation=runtime,
                    evidence_quality=evidence_quality,
                    remediation=_remediation(
                        "production_change_without_approval",
                        permission.get("data_classes", []) if permission else [],
                        ["Provide change-ticket policy, approval policy, production identity export, and runtime write events."],
                    ),
                    operational_context=_operational_context(agent, runtime),
                    description=description,
                )

        for memory_id in agent.get("memory", []):
            memory = next(
                (item for item in evidence.get("agents", {}).get("memory_stores", []) if item.get("id") == memory_id),
                None,
            )
            if not memory:
                continue
            sensitive = set(memory.get("data_classes", [])).intersection(SENSITIVE_DATA_CLASSES)
            if memory.get("persistence") == "persistent" and sensitive and memory.get("retention_policy") in {"", "unknown"}:
                runtime = _runtime_observation(evidence, agent["id"], [])
                runtime = {
                    **runtime,
                    "state": "observed_partial" if any(event.get("event_type") == "agent.memory_write" for event in agent_events) else "not_observed",
                    "explanation": (
                        "A memory-related runtime event was observed for this agent, but retention enforcement was not proven."
                        if any(event.get("event_type") == "agent.memory_write" for event in agent_events)
                        else "No memory retention runtime evidence was observed."
                    ),
                }
                visibility_ids = [f"gap-memory-retention-{memory_id}"] + _agent_metadata_gap_ids(agent)
                evidence_quality = "incomplete"
                score = score_path(
                    {
                        "persistent_memory_with_sensitive_data": f"{memory_id} is persistent and contains {', '.join(sensitive)}",
                        "sensitive_data_medium": f"{memory_id} contains sensitive data classes",
                        "missing_approval": "No retention or redaction policy was provided",
                        "unknown_data_classification": "Memory retention and redaction classification is incomplete",
                        "has_sensitive_or_critical_action": True,
                        "confidences": ["high"],
                    }
                )
                add_path(
                    rule_id="persistent_memory_sensitive_data_gap",
                    title=f"{memory_id} may retain sensitive data without a retention policy",
                    nodes=[node_id("agent", agent["id"]), node_id("memory_store", memory_id)],
                    edges=[edge_id("agent_has_memory", node_id("agent", agent["id"]), node_id("memory_store", memory_id))],
                    evidence_summary=[agent["id"], memory_id, ", ".join(sorted(sensitive))],
                    evidence_lines=[
                        f"{memory.get('source_file')}: {memory_id} persistence={memory.get('persistence')} "
                        f"retention={memory.get('retention_policy')} period={memory.get('retention_period') or 'unknown'} "
                        f"deletion={memory.get('deletion_policy') or 'unknown'} owner={memory.get('owner') or 'unknown'}"
                    ],
                    unknowns=["Retention, redaction, deletion, and memory-write controls were not provided."],
                    blockers=[],
                    controls=[],
                    visibility_gap_ids=visibility_ids,
                    recommended_next_evidence=[
                        "Provide memory retention, redaction, deletion workflow, and memory-write event evidence."
                    ],
                    recommendations=[
                        "add retention policy",
                        "redact PII before memory write",
                        "classify memory store",
                        "add deletion workflow",
                    ],
                    score=score,
                    confidence="high",
                    runtime_observation=runtime,
                    evidence_quality=evidence_quality,
                    remediation=_remediation(
                        "persistent_memory_sensitive_data_gap",
                        sorted(sensitive),
                        ["Provide memory retention, redaction, deletion workflow, and memory-write event evidence."],
                    ),
                    operational_context=_operational_context(agent, runtime),
                    description="Persistent agent memory contains sensitive classes and no concrete retention policy was declared.",
                )

        for tool_id in agent.get("tools", []):
            tool = tools.get(tool_id)
            if not tool:
                continue
            target = tool.get("target_system", "unknown")
            if target in IAM_VISIBILITY_TARGET_SYSTEMS:
                identity_ids = _bound_identity_ids(agent, tool_id) or _agent_identity_ids(agent)
                matching_identity = [
                    identity
                    for identity_id in identity_ids
                    if (identity := identities.get(identity_id)) and identity.get("target_system") == target
                ]
                missing_or_weak = not matching_identity or any(not identity.get("permissions") for identity in matching_identity if identity)
                if missing_or_weak:
                    gap = VisibilityGap(
                        id=f"gap-iam-{agent['id']}-{target}",
                        type="unknown_target_iam_gap",
                        target=f"{agent['id']}:{target}",
                        reason=f"Agent uses {target} tool {tool_id}, but matching identity permissions are missing or weak.",
                        requested_evidence="Provide target-system permission export, OAuth scope export, service account policy, or runtime audit events.",
                        severity="high",
                    )
                    if gap.id not in {item.id for item in gaps}:
                        gaps.append(gap)
                    agent_node = node_id("agent", agent["id"])
                    tool_node = node_id("tool", tool_id)
                    missing_iam_node = node_id("unknown", f"{agent['id']}:{target}:permissions")
                    runtime = _runtime_observation(evidence, agent["id"], [tool_id])
                    visibility_ids = [gap.id] + _agent_metadata_gap_ids(agent)
                    evidence_quality = _evidence_quality(
                        tools=[tool],
                        visibility_gap_ids=visibility_ids,
                        runtime_observation=runtime,
                        has_identity_permission=False,
                        has_data_evidence=False,
                        finding_type="visibility_gap",
                    )
                    score = score_path(
                        {
                            "unknown_identity_permissions": gap.reason,
                            "has_sensitive_or_critical_action": bool(set(tool.get("risk_tags", [])).intersection(DANGEROUS_TAGS | {"sensitive_read"})),
                            "visibility_gap_only": True,
                            "confidences": [tool.get("risk_confidence", "medium")],
                        }
                    )
                    add_path(
                        rule_id="unknown_target_iam_gap",
                        title=f"Potential path: {agent['id']} may use {target} tools, but permission evidence is incomplete.",
                        nodes=[agent_node, tool_node, missing_iam_node],
                        edges=[
                            edge_id("agent_uses_tool", agent_node, tool_node),
                            edge_id("missing_evidence", tool_node, missing_iam_node),
                        ],
                        evidence_summary=[agent["id"], tool_id, f"{target} permissions unknown"],
                        evidence_lines=[f"{tool.get('source_file')}: {tool_id} targets {target}"],
                        unknowns=[gap.reason],
                        blockers=[],
                        controls=[],
                        visibility_gap_ids=visibility_ids,
                        recommended_next_evidence=[gap.requested_evidence],
                        recommendations=[
                            "provide target system permission export",
                            "provide OAuth scope export",
                            "provide service account policy",
                            "provide runtime audit events",
                        ],
                        score=score,
                        confidence=tool.get("risk_confidence", "medium"),
                        related_events=runtime.get("observed_events", []),
                        observation_status=_legacy_observation_status(runtime),
                        runtime_observation=runtime,
                        evidence_quality=evidence_quality,
                        remediation=_remediation("unknown_target_iam_gap", [], [gap.requested_evidence]),
                        operational_context=_operational_context(agent, runtime),
                        description="The tool targets a security-relevant system, but identity permissions were not provided.",
                        finding_type="visibility_gap",
                    )

    offline_analysis = build_offline_control_analysis(evidence)
    existing_gap_ids = {gap.id for gap in gaps}
    agents_by_id = {
        agent.get("id", ""): agent
        for agent in evidence.get("agents", {}).get("agents", [])
        if agent.get("id")
    }
    for row in offline_analysis.get("agent_tool_controls", []):
        agent = agents_by_id.get(row.get("agent", ""), {})
        agent_node = node_id("agent", row.get("agent", "unknown"))
        tool_node = node_id("tool", row.get("tool", "unknown"))
        policy_node = node_id("approval_policy", row.get("approval_policy") or "unknown")
        approval_edge_missing = row.get("policy_decision") not in {"approval_required", "deny", "allow"}
        visibility_ids: list[str] = []
        if row.get("missing_required_controls"):
            gap_id = f"gap-offline-controls-{row.get('agent')}-{row.get('tool')}"
            visibility_ids.append(gap_id)
            if gap_id not in existing_gap_ids:
                gaps.append(
                    VisibilityGap(
                        id=gap_id,
                        type="offline_tool_control_gap",
                        target=f"{row.get('agent')}:{row.get('tool')}",
                        reason=(
                            f"Offline policy evidence for {row.get('tool')} is missing "
                            f"{', '.join(control_label(control) for control in row.get('missing_required_controls', []))}."
                        ),
                        requested_evidence=(
                            "Add local approval-policy evidence with decision and controls for "
                            f"{row.get('tool')}: "
                            f"{', '.join(control_label(control) for control in row.get('missing_required_controls', []))}."
                        ),
                        severity="high",
                    )
                )
                existing_gap_ids.add(gap_id)
            score = score_path(_offline_score_context(row))
            title = (
                f"Offline control gap: {row.get('agent')} uses {row.get('tool')} without "
                f"{', '.join(control_label(control) for control in row.get('missing_required_controls', []))}"
            )
            findings.append(
                Finding(
                    id=_offline_finding_id(
                        "offline_tool_control_gap",
                        [agent_node, tool_node, policy_node],
                        [row.get("agent", ""), row.get("tool", ""), "offline controls missing"],
                    ),
                    title=title,
                    description=(
                        "The local evidence shows a high-risk AI tool, but the offline approval-policy evidence "
                        "does not declare every expected approval, sandbox, egress, secret, identity, DLP, change, or audit control."
                    ),
                    tier=score.tier,
                    score=score.score,
                    confidence=row.get("risk_confidence", "medium"),
                    path=[row.get("agent", ""), row.get("tool", ""), "offline policy controls"],
                    nodes=[agent_node, tool_node, policy_node],
                    edges=[
                        edge_id("agent_uses_tool", agent_node, tool_node),
                        _approval_edge_id(
                            agent or {"approval_policy": row.get("approval_policy", "")},
                            row.get("tool", ""),
                            approval_edge_missing,
                        ),
                    ],
                    evidence=[
                        f"{row.get('source_file')}: {row.get('tool')} risk tags {', '.join(row.get('risk_tags', []))}",
                        f"{row.get('policy_source_file') or 'approval-policy'}: decision={row.get('policy_decision')} rule={row.get('policy_rule') or 'none'}",
                    ],
                    unknowns=[
                        f"Missing offline control: {control_label(control)}"
                        for control in row.get("missing_required_controls", [])
                    ],
                    blockers=[],
                    controls=[f"{control}:{row.get('policy_rule') or 'declared'}" for control in row.get("declared_controls", [])],
                    recommendations=[
                        "add explicit approval or deny policy for high-risk tools",
                        "declare sandbox, egress, secret, identity, DLP, change, and audit controls as applicable",
                        "prefer narrow typed tools over generic execution surfaces",
                    ],
                    source_files=source_files_list,
                    related_events=[],
                    evidence_layer="offline_policy",
                    observation_status="possible_static",
                    path_state="supported",
                    evidence_quality="supported" if row.get("policy_rule") else "incomplete",
                    runtime_observation={"state": "not_observed", "observed_events": [], "session_ids": [], "last_observed_at": "", "sequence_confidence": "low"},
                    remediation=_offline_remediation(row),
                    operational_context=_operational_context(agent, {"last_observed_at": ""}) if agent else {},
                    visibility_gaps=visibility_ids,
                    visibility_gap_priorities=[],
                    recommended_next_evidence=[
                        f"Provide offline policy evidence for {control_label(control)}."
                        for control in row.get("missing_required_controls", [])
                    ],
                    scoring=score,
                    finding_type="offline_control_gap",
                    rule_id="offline_tool_control_gap",
                )
            )
        if row.get("generic_tool"):
            gap_id = f"gap-generic-tool-{row.get('agent')}-{row.get('tool')}"
            if gap_id not in existing_gap_ids:
                gaps.append(
                    VisibilityGap(
                        id=gap_id,
                        type="generic_tool_surface_gap",
                        target=f"{row.get('agent')}:{row.get('tool')}",
                        reason=(
                            f"{row.get('tool')} appears to be a generic or broad tool surface: "
                            f"{', '.join(row.get('broad_reasons', []))}."
                        ),
                        requested_evidence="Replace with narrow typed tools or provide schema/resource constraints and policy controls.",
                        severity="high",
                    )
                )
                existing_gap_ids.add(gap_id)
            score_context = _offline_score_context(row)
            score_context["missing_approval"] = score_context.get("missing_approval") or "Generic tool surface should be narrowed or explicitly controlled"
            score = score_path(score_context)
            findings.append(
                Finding(
                    id=_offline_finding_id(
                        "generic_tool_surface",
                        [agent_node, tool_node],
                        [row.get("agent", ""), row.get("tool", ""), "generic tool"],
                    ),
                    title=f"Generic tool surface: {row.get('agent')} can call {row.get('tool')}",
                    description=(
                        "The tool name, risk tags, or input schema resemble a broad execution, filesystem, network, or query surface. "
                        "Offline review should prefer narrow typed tools with resource constraints."
                    ),
                    tier=score.tier,
                    score=score.score,
                    confidence=row.get("risk_confidence", "medium"),
                    path=[row.get("agent", ""), row.get("tool", ""), "generic tool surface"],
                    nodes=[agent_node, tool_node],
                    edges=[edge_id("agent_uses_tool", agent_node, tool_node)],
                    evidence=[
                        f"{row.get('source_file')}: {row.get('tool')} broadness reasons: {', '.join(row.get('broad_reasons', []))}",
                    ],
                    unknowns=["Parameter-level resource constraints are not proven by current offline evidence."],
                    blockers=[],
                    controls=[f"{control}:{row.get('policy_rule') or 'declared'}" for control in row.get("declared_controls", [])],
                    recommendations=[
                        "replace generic tools with narrow typed operations",
                        "add explicit input schema constraints for paths, commands, URLs, queries, and resource ids",
                        "bind the tool to the least-privilege identity needed for that operation",
                    ],
                    source_files=source_files_list,
                    related_events=[],
                    evidence_layer="offline_static",
                    observation_status="possible_static",
                    path_state="supported",
                    evidence_quality="supported",
                    runtime_observation={"state": "not_observed", "observed_events": [], "session_ids": [], "last_observed_at": "", "sequence_confidence": "low"},
                    remediation=_offline_remediation(row),
                    operational_context=_operational_context(agent, {"last_observed_at": ""}) if agent else {},
                    visibility_gaps=[gap_id],
                    visibility_gap_priorities=[],
                    recommended_next_evidence=["Provide narrow typed tool descriptors or schema/resource constraints."],
                    scoring=score,
                    finding_type="offline_control_gap",
                    rule_id="generic_tool_surface",
                )
            )

    for prompt_row in offline_analysis.get("prompt_boundary_risks", []):
        agent = agents_by_id.get(prompt_row.get("agent", ""), {})
        agent_node = node_id("agent", prompt_row.get("agent", "unknown"))
        policy_node = node_id("approval_policy", prompt_row.get("approval_policy") or "unknown")
        gap_id = f"gap-prompt-boundary-{prompt_row.get('agent')}"
        if gap_id not in existing_gap_ids:
            gaps.append(
                VisibilityGap(
                    id=gap_id,
                    type="system_prompt_security_boundary_gap",
                    target=prompt_row.get("agent", "unknown"),
                    reason="Agent evidence uses prompt-language security instructions while high-risk tool controls are incomplete.",
                    requested_evidence="Move security boundaries into local approval policy, identity, sandbox, egress, DLP, and audit evidence.",
                    severity="high",
                )
            )
            existing_gap_ids.add(gap_id)
        score = score_path(
            {
                "missing_approval": "Prompt text is being used as a security boundary while offline controls are incomplete",
                "has_sensitive_or_critical_action": True,
                "confidences": ["medium"],
            }
        )
        findings.append(
            Finding(
                id=_offline_finding_id(
                    "system_prompt_security_boundary",
                    [agent_node, policy_node],
                    [prompt_row.get("agent", ""), "prompt security boundary"],
                ),
                title=f"Prompt-based security boundary: {prompt_row.get('agent')}",
                description=(
                    "The offline agent evidence contains prompt instructions about secrets, leakage, or malicious input. "
                    "Those instructions are useful context but should not be treated as the security boundary."
                ),
                tier=score.tier,
                score=score.score,
                confidence="medium",
                path=[prompt_row.get("agent", ""), "prompt instructions", "offline controls"],
                nodes=[agent_node, policy_node],
                edges=[],
                evidence=[
                    f"{prompt_row.get('source_file')}: prompt fields {', '.join(prompt_row.get('fields', []))} match {', '.join(prompt_row.get('matched_terms', []))}",
                ],
                unknowns=["No complete offline control evidence was found for every high-risk tool used by this agent."],
                blockers=[],
                controls=[],
                recommendations=[
                    "treat prompt instructions as advisory only",
                    "add policy, sandbox, egress, identity, DLP, and audit evidence for high-risk tools",
                    "keep secrets and credentials out of prompt and agent config evidence",
                ],
                source_files=source_files_list,
                related_events=[],
                evidence_layer="offline_static",
                observation_status="possible_static",
                path_state="possible",
                evidence_quality="incomplete",
                runtime_observation={"state": "not_observed", "observed_events": [], "session_ids": [], "last_observed_at": "", "sequence_confidence": "low"},
                remediation={
                    "recommended_controls": [
                        "authorization policy",
                        "scoped identity",
                        "sandbox_control",
                        "egress_allowlist",
                        "audit_logging",
                    ],
                    "policy_snippet": None,
                    "least_privilege_recommendation": "Move security decisions out of prompts and into offline policy and permission evidence.",
                    "required_next_evidence": ["Provide explicit local policy and control evidence for high-risk tools."],
                    "validation_steps": ["Re-run AgentGuard Graph and confirm this prompt-boundary finding is gone."],
                },
                operational_context=_operational_context(agent, {"last_observed_at": ""}) if agent else {},
                visibility_gaps=[gap_id],
                visibility_gap_priorities=[],
                recommended_next_evidence=["Provide explicit local policy and control evidence for high-risk tools."],
                scoring=score,
                finding_type="offline_control_gap",
                rule_id="system_prompt_security_boundary",
            )
        )

    findings = sorted(findings, key=lambda finding: (-finding.score, finding.id))
    gaps = _prioritize_visibility_gaps(gaps, findings, paths)
    return paths, findings, gaps


def summarize_counts(evidence: dict[str, Any], findings: list[Finding], visibility_gaps: list[VisibilityGap]) -> dict[str, int]:
    inventory = build_inventory(evidence)
    return {
        "agents": len(inventory["agents"]),
        "tools": len(inventory["tools"]),
        "identities": len(inventory["identities"]),
        "data_sources": len(inventory["data_sources"]),
        "findings": len(findings),
        "urgent": sum(1 for finding in findings if finding.tier == "urgent"),
        "high": sum(1 for finding in findings if finding.tier == "high"),
        "medium": sum(1 for finding in findings if finding.tier == "medium"),
        "low": sum(1 for finding in findings if finding.tier == "low"),
        "visibility_gaps": len(visibility_gaps),
        "critical_gaps": sum(1 for gap in visibility_gaps if gap.priority == "critical_gap"),
        "high_gaps": sum(1 for gap in visibility_gaps if gap.priority == "high_gap"),
        "medium_gaps": sum(1 for gap in visibility_gaps if gap.priority == "medium_gap"),
        "low_gaps": sum(1 for gap in visibility_gaps if gap.priority == "low_gap"),
        "possible_static": sum(1 for finding in findings if finding.observation_status == "possible_static"),
        "possible": sum(1 for finding in findings if finding.path_state == "possible"),
        "supported": sum(1 for finding in findings if finding.path_state == "supported"),
        "observed_partial": sum(1 for finding in findings if finding.path_state == "observed_partial"),
        "observed_full": sum(1 for finding in findings if finding.path_state == "observed_full"),
        "observed_allowed": sum(1 for finding in findings if finding.observation_status == "observed_allowed"),
        "observed_blocked": sum(1 for finding in findings if finding.observation_status == "observed_blocked"),
        "confirmed": sum(1 for finding in findings if finding.evidence_quality == "confirmed"),
        "supported_quality": sum(1 for finding in findings if finding.evidence_quality == "supported"),
        "incomplete": sum(1 for finding in findings if finding.evidence_quality == "incomplete"),
        "weak": sum(1 for finding in findings if finding.evidence_quality == "weak"),
        "open_findings": sum(1 for finding in findings if finding.risk_status == "open"),
        "accepted_risk_findings": sum(1 for finding in findings if finding.risk_status == "accepted"),
        "expired_accepted_risk_findings": sum(1 for finding in findings if finding.risk_status == "acceptance_expired"),
        "accepted_risk_high_or_urgent": sum(
            1 for finding in findings if finding.risk_status == "accepted" and finding.tier in {"urgent", "high"}
        ),
    }
