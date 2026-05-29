"""Report assembly helpers for findings."""

from __future__ import annotations

from datetime import date, datetime, timezone
import hashlib
import json
from typing import Any

from .. import __version__
from ..iam_analysis import build_iam_analysis
from ..manifest import empty_evidence_manifest_status
from ..models import AttackPath, Finding, Graph, VisibilityGap
from ..offline_analysis import build_offline_control_analysis
from ..policy_analysis import build_policy_analysis
from ..privacy_analysis import build_privacy_analysis
from ..remediation import build_remediation_plan
from .builder import build_inventory
from .paths import summarize_counts


_GAP_PRIORITY_RANK = {"critical_gap": 0, "high_gap": 1, "medium_gap": 2, "low_gap": 3}
_RISK_STATUS_OPEN = {"status": "open", "accepted": False, "expired": False, "expires_at": ""}
_ACCEPTANCE_SCOPE_KEYS = ["finding_id", "path_id", "rule_id", "agent", "owner", "environment", "business_unit"]
_TOOL_EVENT_TYPES = {
    "agent.approval_requested",
    "agent.approval_granted",
    "agent.approval_denied",
    "agent.external_send",
    "agent.memory_read",
    "agent.memory_write",
    "agent.policy_denied",
    "agent.tool_call",
    "agent.tool_result",
}


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique_values: list[str] = []
    for value in values:
        if value and value not in seen:
            unique_values.append(value)
            seen.add(value)
    return unique_values


def _open_risk_status() -> dict[str, Any]:
    return dict(_RISK_STATUS_OPEN)


def _is_expired(expires_at: str) -> bool:
    if not expires_at:
        return False
    try:
        return date.fromisoformat(expires_at) < date.today()
    except ValueError:
        return False


def _scope_specificity(scope: dict[str, Any]) -> int:
    return sum(1 for key in _ACCEPTANCE_SCOPE_KEYS if scope.get(key))


def _agent_id_for_item(item: Any) -> str:
    context = getattr(item, "operational_context", {}) or {}
    if context.get("agent_id"):
        return str(context["agent_id"])
    for node in getattr(item, "nodes", []) or []:
        if isinstance(node, str) and node.startswith("agent:"):
            return node.split(":", 1)[1]
    return ""


def _path_id_for_item(item: Any) -> str:
    item_id = str(getattr(item, "id", ""))
    if item_id.startswith("finding-"):
        return item_id.replace("finding-", "path-", 1)
    return item_id


def _acceptance_match(item: Any, acceptance: dict[str, Any]) -> list[str]:
    scope = acceptance.get("scope") if isinstance(acceptance.get("scope"), dict) else {}
    if not _scope_specificity(scope):
        return []
    context = getattr(item, "operational_context", {}) or {}
    matched: list[str] = []
    checks = {
        "finding_id": str(getattr(item, "id", "")),
        "path_id": _path_id_for_item(item),
        "rule_id": str(getattr(item, "rule_id", "")),
        "agent": _agent_id_for_item(item),
        "owner": str(context.get("owner", "")),
        "environment": str(context.get("environment", "")),
        "business_unit": str(context.get("business_unit", "")),
    }
    for key, expected in scope.items():
        if key not in checks:
            continue
        if str(expected) != checks[key]:
            return []
        matched.append(key)
    return matched


def _accepted_risk_metadata(
    acceptance: dict[str, Any],
    *,
    expired: bool,
    matched_by: list[str],
    specificity: int,
) -> dict[str, Any]:
    return {
        "status": "expired" if expired else "accepted",
        "accepted": not expired,
        "expired": expired,
        "id": acceptance.get("id", ""),
        "owner": acceptance.get("owner", ""),
        "reason": acceptance.get("reason", ""),
        "ticket": acceptance.get("ticket", ""),
        "accepted_at": acceptance.get("accepted_at", ""),
        "expires_at": acceptance.get("expires_at", ""),
        "scope": acceptance.get("scope", {}),
        "matched_by": matched_by,
        "scope_specificity": specificity,
        "source_file": acceptance.get("source_file", ""),
    }


def _apply_acceptance(item: Any, acceptance: dict[str, Any], matched_by: list[str]) -> None:
    scope = acceptance.get("scope") if isinstance(acceptance.get("scope"), dict) else {}
    specificity = _scope_specificity(scope)
    current = getattr(item, "accepted_risk", {}) or {}
    if current.get("status") in {"accepted", "expired"} and int(current.get("scope_specificity", -1)) > specificity:
        return
    expired = _is_expired(str(acceptance.get("expires_at") or ""))
    item.risk_status = "acceptance_expired" if expired else "accepted"
    item.accepted_risk = _accepted_risk_metadata(
        acceptance,
        expired=expired,
        matched_by=matched_by,
        specificity=specificity,
    )


def _apply_risk_acceptances(
    evidence: dict[str, Any],
    findings: list[Finding],
    attack_paths: list[AttackPath],
) -> None:
    for item in [*findings, *attack_paths]:
        item.risk_status = "open"
        item.accepted_risk = _open_risk_status()
    acceptances = (evidence.get("agents") or {}).get("risk_acceptances", [])
    for acceptance in acceptances:
        if not isinstance(acceptance, dict) or acceptance.get("status", "accepted") != "accepted":
            continue
        for item in [*attack_paths, *findings]:
            matched_by = _acceptance_match(item, acceptance)
            if matched_by:
                _apply_acceptance(item, acceptance, matched_by)


def _review_decision(findings: list[Finding], visibility_gaps: list[VisibilityGap]) -> dict[str, Any]:
    expired_acceptances = [finding for finding in findings if finding.risk_status == "acceptance_expired"]
    active_accepted = [finding for finding in findings if finding.risk_status == "accepted"]
    active_findings = [finding for finding in findings if finding.risk_status != "accepted"]
    high_or_urgent = [finding for finding in active_findings if finding.tier in {"urgent", "high"}]
    accepted_high_or_urgent = [finding for finding in active_accepted if finding.tier in {"urgent", "high"}]
    critical_gaps = [
        gap
        for gap in visibility_gaps
        if gap.priority == "critical_gap" or gap.type in {"unknown_target_iam_gap", "target_system_permissions_unknown"}
    ]
    approval_gap_findings = [
        finding
        for finding in high_or_urgent
        if any("gap-approval" in gap_id for gap_id in finding.visibility_gaps)
    ]
    strong_findings = [
        finding
        for finding in high_or_urgent
        if finding.evidence_quality in {"confirmed", "supported"}
    ]
    incomplete_high = [
        finding
        for finding in high_or_urgent
        if finding.evidence_quality == "incomplete"
        or any("gap-iam" in gap_id or "gap-tool" in gap_id for gap_id in finding.visibility_gaps)
    ]

    if not findings:
        return {
            "decision": "no_high_risk_paths_found",
            "label": "No high-risk paths found",
            "reason": "No attack-path findings were produced from the supplied evidence.",
            "reasons": [],
            "required_actions": ["Keep collecting runtime and identity evidence for future reviews."],
        }
    if expired_acceptances:
        return {
            "decision": "needs_more_evidence",
            "label": "Accepted risk expired",
            "reason": "One or more findings match expired accepted-risk metadata.",
            "reasons": [
                f"{finding.title} expired {finding.accepted_risk.get('expires_at', '')}"
                for finding in expired_acceptances[:3]
            ],
            "required_actions": [
                "Renew, revoke, or close expired accepted-risk records.",
                "Review current evidence before extending any accepted risk.",
                "Re-run AgentGuard Graph after updating accepted-risk metadata.",
            ],
        }
    if critical_gaps and any(finding.evidence_quality == "incomplete" for finding in findings):
        return {
            "decision": "needs_more_evidence",
            "label": "Needs more evidence",
            "reason": "Identity or permission evidence is missing for one or more security-relevant paths.",
            "reasons": [gap.reason for gap in critical_gaps[:3]],
            "required_actions": [
                "Provide missing identity, permission, data classification, or runtime evidence.",
                "Resolve critical visibility gaps.",
                "Re-run AgentGuard Graph before approval.",
            ],
        }
    if strong_findings and any(finding.tier == "urgent" for finding in strong_findings) and approval_gap_findings:
        return {
            "decision": "block_launch",
            "label": "Block launch",
            "reason": "Urgent supported or confirmed paths are missing required approval controls.",
            "reasons": [
                f"{finding.title} ({finding.evidence_quality}, {finding.path_state})"
                for finding in strong_findings[:3]
            ],
            "required_actions": [
                "Add approval rules for the high-risk actions.",
                "Provide target-system permission exports for affected agents.",
                "Re-run AgentGuard Graph and confirm the review decision changes.",
            ],
        }
    if incomplete_high or critical_gaps:
        return {
            "decision": "needs_more_evidence",
            "label": "Needs more evidence",
            "reason": "High-impact paths have missing identity, permission, tool, or other validation evidence.",
            "reasons": [gap.reason for gap in critical_gaps[:3]]
            or [finding.title for finding in incomplete_high[:3]],
            "required_actions": [
                "Provide missing identity, permission, data classification, or runtime evidence.",
                "Resolve critical visibility gaps.",
                "Re-run AgentGuard Graph before approval.",
            ],
        }
    if approval_gap_findings:
        return {
            "decision": "approve_with_conditions",
            "label": "Approve with conditions",
            "reason": "High-risk paths appear fixable with explicit approval or control policy changes.",
            "reasons": [finding.title for finding in approval_gap_findings[:3]],
            "required_actions": [
                "Add the suggested approval policy rules.",
                "Validate controls with runtime events.",
                "Track remaining visibility gaps as review conditions.",
            ],
        }
    if accepted_high_or_urgent and not high_or_urgent:
        return {
            "decision": "approve_with_conditions",
            "label": "Accepted risk active",
            "reason": "High-impact findings are covered by unexpired accepted-risk metadata.",
            "reasons": [
                f"{finding.title} accepted until {finding.accepted_risk.get('expires_at', 'unspecified')}"
                for finding in accepted_high_or_urgent[:3]
            ],
            "required_actions": [
                "Track accepted-risk expiration dates.",
                "Review exceptions before renewal.",
                "Re-run AgentGuard Graph when scope, owner, policy, or runtime evidence changes.",
            ],
        }
    if high_or_urgent:
        return {
            "decision": "approve_with_conditions",
            "label": "Approve with conditions",
            "reason": "High-risk paths remain but have no launch-blocking missing evidence in this local report.",
            "reasons": [finding.title for finding in high_or_urgent[:3]],
            "required_actions": ["Review recommended controls and validation steps before launch."],
        }
    return {
        "decision": "monitor_only",
        "label": "Monitor only",
        "reason": "Only low or medium findings were produced from the supplied evidence.",
        "reasons": [],
        "required_actions": ["Monitor runtime observations and refresh identity evidence periodically."],
    }


def _review_brief(
    summary: dict[str, int],
    review_decision: dict[str, Any],
    findings: list[Finding],
    visibility_gaps: list[VisibilityGap],
) -> dict[str, Any]:
    sorted_findings = sorted(findings, key=lambda item: (-int(item.score), item.id))
    primary = sorted_findings[0] if sorted_findings else None
    sorted_gaps = sorted(
        visibility_gaps,
        key=lambda gap: (_GAP_PRIORITY_RANK.get(gap.priority, 2), gap.id),
    )
    top_gaps = [
        {
            "id": gap.id,
            "priority": gap.priority,
            "type": gap.type,
            "target": gap.target,
            "reason": gap.reason,
            "affected_findings": gap.affected_findings[:3],
        }
        for gap in sorted_gaps[:3]
    ]
    top_actions = _unique(
        list(review_decision.get("required_actions", []))
        + [
            action
            for finding in sorted_findings[:3]
            for action in (finding.remediation.get("validation_steps", []) if finding.remediation else [])
        ]
    )[:5]
    posture_parts = [
        f"{summary.get('confirmed', 0)} confirmed",
        f"{summary.get('supported', 0)} supported",
        f"{summary.get('incomplete', 0)} incomplete",
        f"{summary.get('weak', 0)} weak",
    ]
    observation_parts = [
        f"{summary.get('observed_full', 0)} observed full",
        f"{summary.get('observed_partial', 0)} observed partial",
        f"{summary.get('observed_blocked', 0)} observed blocked",
    ]
    primary_summary: dict[str, Any] = {}
    if primary:
        context = primary.operational_context or {}
        primary_summary = {
            "id": primary.id,
            "title": primary.title,
            "tier": primary.tier,
            "score": primary.score,
            "raw_points": primary.scoring.raw_points if primary.scoring else primary.score,
            "evidence_quality": primary.evidence_quality,
            "path_state": primary.path_state,
            "risk_status": primary.risk_status,
            "accepted_risk_expires_at": primary.accepted_risk.get("expires_at", ""),
            "owner": context.get("owner"),
            "environment": context.get("environment"),
            "control_status": "blocked"
            if primary.runtime_observation.get("state") == "observed_blocked"
            else "approval_missing"
            if any("gap-approval" in gap_id for gap_id in primary.visibility_gaps)
            else "approval_present"
            if primary.blockers or primary.controls
            else "unknown",
        }
    return {
        "headline": review_decision.get("label", "Unknown decision"),
        "decision": review_decision.get("decision", "unknown"),
        "posture": "; ".join(posture_parts),
        "runtime_posture": "; ".join(observation_parts),
        "primary_risk": primary_summary,
        "top_visibility_gaps": top_gaps,
        "top_actions": top_actions,
    }


def _list_size(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0


def _source_status(count: int, partial: bool = False) -> str:
    if count <= 0:
        return "missing"
    if partial:
        return "partial"
    return "present"


def _evidence_guide(evidence: dict[str, Any], findings: list[Finding], visibility_gaps: list[VisibilityGap]) -> dict[str, Any]:
    agents = (evidence.get("agents") or {}).get("agents") or []
    tools = (evidence.get("mcp") or {}).get("tools") or []
    identities = (evidence.get("identity") or {}).get("identities") or []
    data_sources = (evidence.get("data_catalog") or {}).get("data_sources") or []
    policies = (evidence.get("approval_policy") or {}).get("policies") or []
    events = (evidence.get("events") or {}).get("events") or []
    identities_without_permissions = [
        identity.get("id")
        for identity in identities
        if not identity.get("permissions") and not identity.get("scopes")
    ]
    agents_without_owner = [agent.get("id") for agent in agents if not agent.get("owner")]
    agents_without_environment = [agent.get("id") for agent in agents if not agent.get("environment")]
    sorted_gaps = sorted(
        visibility_gaps,
        key=lambda gap: (_GAP_PRIORITY_RANK.get(gap.priority, 2), gap.id),
    )
    top_missing = [
        {
            "id": gap.id,
            "priority": gap.priority,
            "type": gap.type,
            "target": gap.target,
            "reason": gap.reason,
            "requested_evidence": gap.requested_evidence,
            "affected_findings": gap.affected_findings[:5],
        }
        for gap in sorted_gaps[:8]
    ]
    high_gap_targets = [gap.target for gap in sorted_gaps if gap.priority in {"critical_gap", "high_gap"}][:5]
    evidence_sources = [
        {
            "kind": "agent_inventory",
            "label": "Agent inventory",
            "status": _source_status(_list_size(agents), bool(agents_without_owner or agents_without_environment)),
            "count": _list_size(agents),
            "notes": "Includes owner and environment when supplied.",
        },
        {
            "kind": "tool_manifest",
            "label": "Tool and API manifests",
            "status": _source_status(_list_size(tools)),
            "count": _list_size(tools),
            "notes": "MCP, OpenAPI, LangChain, custom, or runtime tool metadata.",
        },
        {
            "kind": "identity_permissions",
            "label": "Identity permissions",
            "status": _source_status(_list_size(identities), bool(identities_without_permissions)),
            "count": _list_size(identities),
            "notes": "OAuth scopes, service account policy, app permissions, IAM, or RBAC exports.",
        },
        {
            "kind": "data_classification",
            "label": "Data classification",
            "status": _source_status(_list_size(data_sources)),
            "count": _list_size(data_sources),
            "notes": "Maps target systems, objects, fields, or stores to data classes.",
        },
        {
            "kind": "approval_controls",
            "label": "Approval controls",
            "status": _source_status(_list_size(policies)),
            "count": _list_size(policies),
            "notes": "Approval, deny, sandbox, egress, or policy-block evidence.",
        },
        {
            "kind": "runtime_events",
            "label": "Runtime events",
            "status": _source_status(_list_size(events)),
            "count": _list_size(events),
            "notes": "Tool-call, approval, allow, block, and session correlation logs.",
        },
    ]
    recommended_next_inputs = [
        {
            "file": "identity.json",
            "why": "Permission evidence upgrades possible or incomplete paths to supported paths.",
        },
        {
            "file": "events.jsonl",
            "why": "Runtime events separate possible paths from observed partial, observed full, allowed, and blocked paths.",
        },
        {
            "file": "approval-policy.json",
            "why": "Control evidence distinguishes missing approval from approval required, denied, granted, or policy blocked.",
        },
        {
            "file": "data-catalog.json",
            "why": "Data classification tells reviewers whether a tool can reach PII, billing data, secrets, source code, or production assets.",
        },
        {
            "file": "agentguard.json",
            "why": "Owner, environment, runtime, input trust, memory retention, and business context make findings assignable.",
        },
    ]
    if not top_missing:
        top_missing = [
            {
                "id": "none",
                "priority": "low_gap",
                "type": "no_priority_visibility_gaps",
                "target": "report",
                "reason": "No priority visibility gaps were produced from the supplied evidence.",
                "requested_evidence": "Refresh identity, policy, and runtime evidence periodically.",
                "affected_findings": [],
            }
        ]
    return {
        "audience": "security_review",
        "summary": (
            "Use this guide to request the evidence needed to turn possible paths into supported or observed review outcomes."
        ),
        "evidence_sources": evidence_sources,
        "top_missing_evidence": top_missing,
        "high_priority_targets": high_gap_targets,
        "collection_commands": [
            "agentguard-graph collect --project-dir . --out agent-evidence/",
            "agentguard-graph validate --evidence-dir agent-evidence/ --json",
            "agentguard-graph scan --evidence-dir agent-evidence/ --out outputs/agent-risk.json --markdown outputs/agent-risk.md --html outputs/agent-risk.html",
        ],
        "security_team_questions": [
            "Which production agents are in scope, who owns them, and what business process do they support?",
            "Which OAuth apps, service accounts, API keys, or workload identities does each agent run as?",
            "Can the platform team export target-system permissions for every identity used by the agent?",
            "Do runtime logs include session ids, tool ids, decisions, policy ids, and blocked attempts?",
            "Which data catalog or classification export proves whether reached objects contain sensitive data?",
            "Which approval, egress, sandbox, or deny controls apply to external sends, financial actions, production writes, command execution, and memory retention?",
        ],
        "recommended_next_inputs": recommended_next_inputs,
        "handoff_checklist": [
            "Send the evidence pack directory, not screenshots, to the reviewer.",
            "Include raw permission exports even when they look redundant with tool manifests.",
            "Preserve runtime session ids and event ids so observed paths can be correlated.",
            "Treat missing evidence as a visibility gap until the next scan proves otherwise.",
        ],
        "finding_count": len(findings),
    }


def _stable_runtime_path_id(agent: str, session_id: str, event_ids: list[str]) -> str:
    payload = json.dumps(
        {"agent": agent, "session_id": session_id, "event_ids": event_ids},
        sort_keys=True,
        separators=(",", ":"),
    )
    return "runtime-path-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def _event_key(event: dict[str, Any], index: int) -> str:
    event_id = str(event.get("id", ""))
    if event_id:
        return event_id
    return f"line:{event.get('line', index)}"


def _parse_event_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _event_requires_tool(event: dict[str, Any]) -> bool:
    return str(event.get("event_type", "")) in _TOOL_EVENT_TYPES


def _runtime_diagnostic(
    *,
    diagnostic_id: str,
    diagnostic_type: str,
    event: dict[str, Any],
    index: int,
    message: str,
    repair: str,
    previous_event_id: str = "",
) -> dict[str, Any]:
    return {
        "id": diagnostic_id,
        "type": diagnostic_type,
        "event_id": str(event.get("id", "")),
        "event_key": _event_key(event, index),
        "agent": str(event.get("agent", "")),
        "session_id": str(event.get("session_id", "")),
        "tool": str(event.get("tool", "")),
        "timestamp": str(event.get("timestamp", "")),
        "source_file": str(event.get("source_file", "")),
        "line": event.get("line", index),
        "previous_event_id": previous_event_id,
        "message": message,
        "repair": repair,
    }


def _runtime_event_diagnostics(events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    counts = {
        "missing_session_id": 0,
        "missing_agent": 0,
        "missing_tool": 0,
        "missing_timestamp": 0,
        "invalid_timestamp": 0,
        "inconsistent_timestamps": 0,
    }
    diagnostics: list[dict[str, Any]] = []
    ordered_sessions: dict[tuple[str, str], list[tuple[int, dict[str, Any], datetime]]] = {}

    for index, event in enumerate(events, start=1):
        event_key = _event_key(event, index)
        agent = str(event.get("agent", ""))
        session_id = str(event.get("session_id", ""))
        timestamp = str(event.get("timestamp", ""))
        parsed_timestamp = _parse_event_timestamp(timestamp)

        if not session_id:
            counts["missing_session_id"] += 1
            diagnostics.append(
                _runtime_diagnostic(
                    diagnostic_id=f"runtime-diagnostic-{event_key}-missing-session",
                    diagnostic_type="missing_session_id",
                    event=event,
                    index=index,
                    message="Runtime event cannot be correlated to a session.",
                    repair="Export trace_id, run_id, conversation_id, request_id, or session_id from the runtime log.",
                )
            )
        if not agent:
            counts["missing_agent"] += 1
            diagnostics.append(
                _runtime_diagnostic(
                    diagnostic_id=f"runtime-diagnostic-{event_key}-missing-agent",
                    diagnostic_type="missing_agent",
                    event=event,
                    index=index,
                    message="Runtime event does not identify the agent that executed it.",
                    repair="Include agent, agent_id, workflow, app, service, repository, or runtime name in the export.",
                )
            )
        if _event_requires_tool(event) and not str(event.get("tool", "")):
            counts["missing_tool"] += 1
            diagnostics.append(
                _runtime_diagnostic(
                    diagnostic_id=f"runtime-diagnostic-{event_key}-missing-tool",
                    diagnostic_type="missing_tool",
                    event=event,
                    index=index,
                    message="Tool event does not name the tool or action.",
                    repair="Include tool, tool_name, function, method, action, operation, or resource in the export.",
                )
            )
        if not timestamp:
            counts["missing_timestamp"] += 1
            diagnostics.append(
                _runtime_diagnostic(
                    diagnostic_id=f"runtime-diagnostic-{event_key}-missing-timestamp",
                    diagnostic_type="missing_timestamp",
                    event=event,
                    index=index,
                    message="Runtime event has no timestamp.",
                    repair="Export ISO 8601 timestamp, time, eventTime, created_at, started_at, or startTime.",
                )
            )
        elif parsed_timestamp is None:
            counts["invalid_timestamp"] += 1
            diagnostics.append(
                _runtime_diagnostic(
                    diagnostic_id=f"runtime-diagnostic-{event_key}-invalid-timestamp",
                    diagnostic_type="invalid_timestamp",
                    event=event,
                    index=index,
                    message="Runtime event timestamp is not ISO 8601 parseable.",
                    repair="Export timestamps as ISO 8601 values, preferably with a timezone or trailing Z.",
                )
            )

        if agent and session_id and parsed_timestamp is not None:
            ordered_sessions.setdefault((agent, session_id), []).append((index, event, parsed_timestamp))

    for session_events in ordered_sessions.values():
        previous_index, previous_event, previous_timestamp = session_events[0]
        for index, event, timestamp in session_events[1:]:
            if timestamp < previous_timestamp:
                counts["inconsistent_timestamps"] += 1
                event_key = _event_key(event, index)
                diagnostics.append(
                    _runtime_diagnostic(
                        diagnostic_id=f"runtime-diagnostic-{event_key}-timestamp-order",
                        diagnostic_type="inconsistent_timestamp",
                        event=event,
                        index=index,
                        message="Runtime event timestamp is earlier than the previous event in the same session.",
                        repair="Export monotonic event order, preserve original sequence numbers, or fix clock skew in the tracing store.",
                        previous_event_id=str(previous_event.get("id", "")) or _event_key(previous_event, previous_index),
                    )
                )
            if timestamp >= previous_timestamp:
                previous_index, previous_event, previous_timestamp = index, event, timestamp

    return diagnostics, counts


def _runtime_event_quality(events: list[dict[str, Any]], diagnostics: list[dict[str, Any]], counts: dict[str, int]) -> dict[str, Any]:
    total_events = len(events)
    diagnostic_event_keys = {diagnostic["event_key"] for diagnostic in diagnostics}
    low_correlation_events = len(diagnostic_event_keys)
    clean_events = max(total_events - low_correlation_events, 0)
    if not total_events:
        return {
            "score": 0,
            "grade": "no_runtime",
            "clean_events": 0,
            "low_correlation_events": 0,
            "diagnostic_count": 0,
            "reasons": ["No runtime events were provided."],
        }

    penalty = (
        (counts["missing_session_id"] * 20)
        + (counts["missing_agent"] * 20)
        + (counts["missing_tool"] * 15)
        + (counts["missing_timestamp"] * 10)
        + (counts["invalid_timestamp"] * 10)
        + (counts["inconsistent_timestamps"] * 10)
    )
    score = max(0, min(100, round((clean_events / total_events) * 100) - round(penalty / total_events)))
    if score >= 90:
        grade = "clean"
    elif score >= 70:
        grade = "usable"
    elif score >= 40:
        grade = "low_correlation"
    else:
        grade = "unusable"
    reasons = [
        label.replace("_", " ")
        for label, count in counts.items()
        if count
    ]
    return {
        "score": score,
        "grade": grade,
        "clean_events": clean_events,
        "low_correlation_events": low_correlation_events,
        "diagnostic_count": len(diagnostics),
        "reasons": reasons or ["All runtime events have agent, session, tool, and timestamp correlation fields."],
    }


def _sessionless_reason(event: dict[str, Any]) -> str:
    reasons = []
    if not str(event.get("agent", "")):
        reasons.append("missing agent")
    if not str(event.get("session_id", "")):
        reasons.append("missing session_id")
    return ", ".join(reasons) or "missing correlation fields"


def _runtime_reconstruction(evidence: dict[str, Any]) -> dict[str, Any]:
    raw_events = (evidence.get("events") or {}).get("events") or []
    diagnostics, diagnostic_counts = _runtime_event_diagnostics(raw_events)
    quality = _runtime_event_quality(raw_events, diagnostics, diagnostic_counts)
    diagnostics_by_session: dict[tuple[str, str], list[str]] = {}
    for diagnostic in diagnostics:
        agent = diagnostic.get("agent", "")
        session_id = diagnostic.get("session_id", "")
        if agent and session_id:
            diagnostics_by_session.setdefault((agent, session_id), []).append(diagnostic["id"])
    events = sorted(
        raw_events,
        key=lambda item: (item.get("timestamp", ""), item.get("line", 0), item.get("id", "")),
    )
    sessions_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    sessionless_events: list[dict[str, Any]] = []
    for event in events:
        agent = str(event.get("agent", ""))
        session_id = str(event.get("session_id", ""))
        if agent and session_id:
            sessions_by_key.setdefault((agent, session_id), []).append(event)
        else:
            sessionless_events.append(event)

    sessions: list[dict[str, Any]] = []
    event_derived_paths: list[dict[str, Any]] = []
    for (agent, session_id), session_events in sorted(sessions_by_key.items()):
        event_ids = [event.get("id", "") for event in session_events if event.get("id")]
        tool_events = [event for event in session_events if event.get("tool")]
        observed_sequence = [event.get("tool", "") for event in tool_events]
        decisions = sorted({event.get("decision", "") for event in session_events if event.get("decision")})
        data_classes = sorted(
            {
                data_class
                for event in session_events
                for data_class in (event.get("data_classes") or [])
                if data_class
            }
        )
        blocked_events = [
            event.get("id", "")
            for event in session_events
            if event.get("decision") in {"blocked", "deny", "denied"} and event.get("id")
        ]
        allowed_events = [
            event.get("id", "")
            for event in session_events
            if event.get("decision") in {"allow", "allowed"} and event.get("id")
        ]
        session_summary = {
            "agent": agent,
            "session_id": session_id,
            "started_at": session_events[0].get("timestamp", ""),
            "ended_at": session_events[-1].get("timestamp", ""),
            "input_sources": sorted({event.get("input_source", "") for event in session_events if event.get("input_source")}),
            "input_trust": sorted({event.get("input_trust", "") for event in session_events if event.get("input_trust")}),
            "event_ids": event_ids,
            "event_count": len(session_events),
            "observed_sequence": observed_sequence,
            "decisions": decisions,
            "allowed_events": allowed_events,
            "blocked_events": blocked_events,
            "data_classes": data_classes,
            "sequence_confidence": "high" if len(tool_events) > 1 else "medium" if tool_events else "low",
            "event_quality": "low_correlation" if diagnostics_by_session.get((agent, session_id)) else "clean",
            "diagnostics": diagnostics_by_session.get((agent, session_id), []),
        }
        sessions.append(session_summary)
        if len(tool_events) >= 2:
            path_event_ids = [event.get("id", "") for event in tool_events if event.get("id")]
            event_derived_paths.append(
                {
                    "id": _stable_runtime_path_id(agent, session_id, path_event_ids),
                    "agent": agent,
                    "session_id": session_id,
                    "state": "observed_blocked" if blocked_events else "observed_full",
                    "tools": observed_sequence,
                    "event_ids": path_event_ids,
                    "started_at": tool_events[0].get("timestamp", ""),
                    "ended_at": tool_events[-1].get("timestamp", ""),
                    "decisions": sorted({event.get("decision", "") for event in tool_events if event.get("decision")}),
                    "data_classes": data_classes,
                    "blocked_events": blocked_events,
                    "sequence_confidence": "high",
                }
            )

    return {
        "summary": {
            "events": len(events),
            "sessions": len(sessions),
            "event_derived_paths": len(event_derived_paths),
            "sessionless_events": len(sessionless_events),
            "diagnostics": len(diagnostics),
            "missing_session_id": diagnostic_counts["missing_session_id"],
            "missing_agent": diagnostic_counts["missing_agent"],
            "missing_tool": diagnostic_counts["missing_tool"],
            "missing_timestamp": diagnostic_counts["missing_timestamp"],
            "invalid_timestamp": diagnostic_counts["invalid_timestamp"],
            "inconsistent_timestamps": diagnostic_counts["inconsistent_timestamps"],
            "clean_events": quality["clean_events"],
            "low_correlation_events": quality["low_correlation_events"],
        },
        "event_quality": quality,
        "diagnostics": diagnostics,
        "sessions": sessions,
        "event_derived_paths": event_derived_paths,
        "sessionless_events": [
            {
                "id": event.get("id", ""),
                "agent": event.get("agent", ""),
                "tool": event.get("tool", ""),
                "timestamp": event.get("timestamp", ""),
                "reason": _sessionless_reason(event),
            }
            for event in sessionless_events
        ],
    }


def assemble_report(
    evidence: dict[str, Any],
    graph: Graph,
    findings: list[Finding],
    attack_paths: list[AttackPath],
    visibility_gaps: list[VisibilityGap],
    evidence_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _apply_risk_acceptances(evidence, findings, attack_paths)
    summary = summarize_counts(evidence, findings, visibility_gaps)
    iam_analysis = build_iam_analysis(evidence)
    privacy_analysis = build_privacy_analysis(evidence, graph, findings, visibility_gaps)
    policy_analysis = build_policy_analysis(evidence)
    offline_control_analysis = build_offline_control_analysis(evidence)
    evidence_guide = _evidence_guide(evidence, findings, visibility_gaps)
    finding_rows = [finding.to_dict() for finding in findings]
    attack_path_rows = [path.to_dict() for path in attack_paths]
    visibility_gap_rows = [gap.to_dict() for gap in visibility_gaps]
    remediation_plan = build_remediation_plan(
        evidence,
        findings=finding_rows,
        visibility_gaps=visibility_gap_rows,
        offline_control_analysis=offline_control_analysis,
        policy_analysis=policy_analysis,
        iam_analysis=iam_analysis,
        privacy_analysis=privacy_analysis,
        evidence_guide=evidence_guide,
    )
    summary.update(
        {
            "explicit_bindings": iam_analysis["summary"].get("explicit_bindings", 0),
            "inferred_bindings": iam_analysis["summary"].get("inferred_bindings", 0),
            "ambiguous_bindings": iam_analysis["summary"].get("ambiguous_bindings", 0),
            "unbound_tools": iam_analysis["summary"].get("unbound_tools", 0),
            "unused_identities": iam_analysis["summary"].get("unused_identities", 0),
            "unused_permissions": iam_analysis["summary"].get("unused_permissions", 0),
            "privacy_classification_gaps": privacy_analysis["summary"].get("classification_gaps", 0),
            "memory_retention_gaps": privacy_analysis["summary"].get("memory_retention_gaps", 0),
            "policy_evaluations": policy_analysis["summary"].get("policy_evaluations", 0),
            "policy_evaluation_gaps": policy_analysis["summary"].get("gaps", 0),
            "policy_rule_risks": policy_analysis["summary"].get("policy_rule_risks", 0),
            "generic_tools": offline_control_analysis["summary"].get("generic_tools", 0),
            "tools_missing_required_controls": offline_control_analysis["summary"].get("tools_missing_required_controls", 0),
            "prompt_boundary_risks": offline_control_analysis["summary"].get("prompt_boundary_risks", 0),
        }
    )
    review_decision = _review_decision(findings, visibility_gaps)
    return {
        "schema_version": "0.1",
        "tool": {"name": "agentguard-graph", "version": __version__},
        "summary": summary,
        "review_decision": review_decision,
        "review_brief": _review_brief(summary, review_decision, findings, visibility_gaps),
        "evidence_manifest": evidence_manifest or empty_evidence_manifest_status("not_provided"),
        "evidence_guide": evidence_guide,
        "remediation_plan": remediation_plan,
        "iam_analysis": iam_analysis,
        "offline_control_analysis": offline_control_analysis,
        "policy_analysis": policy_analysis,
        "privacy_analysis": privacy_analysis,
        "runtime_reconstruction": _runtime_reconstruction(evidence),
        "inventory": build_inventory(evidence),
        "graph": graph.to_dict(),
        "findings": finding_rows,
        "attack_paths": attack_path_rows,
        "visibility_gaps": visibility_gap_rows,
    }
