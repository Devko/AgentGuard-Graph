"""Deterministic report-level remediation planning."""

from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from typing import Any


_PRIORITY_RANK = {"P1": 0, "P2": 1, "P3": 2}
_TIER_PRIORITY = {"urgent": "P1", "high": "P1", "medium": "P2", "low": "P3", "informational": "P3"}
_GAP_PRIORITY = {"critical_gap": "P1", "high_gap": "P1", "medium_gap": "P2", "low_gap": "P3"}


def _string(value: Any, default: str = "") -> str:
    text = str(value or "").strip()
    return text or default


def _strings(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _string(value)
        if text and text not in seen:
            result.append(text)
            seen.add(text)
    return result


def _stable_id(seed: dict[str, Any]) -> str:
    payload = json.dumps(seed, sort_keys=True, separators=(",", ":"))
    return "remediation-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def _category_from_text(*values: Any) -> str:
    text = " ".join(_string(value).lower() for value in values)
    if any(token in text for token in ["iam", "identity", "permission", "least privilege", "scope", "binding"]):
        return "identity"
    if any(token in text for token in ["privacy", "classification", "retention", "pii", "data catalog", "regulated"]):
        return "data_protection"
    if any(token in text for token in ["egress", "external", "send"]):
        return "egress"
    if any(token in text for token in ["audit", "log"]):
        return "audit"
    if any(token in text for token in ["sandbox", "command", "shell", "exec"]):
        return "sandbox"
    if any(token in text for token in ["prompt", "boundary", "instruction"]):
        return "prompt_boundary"
    if any(token in text for token in ["generic", "tool surface", "typed tool"]):
        return "tool_surface"
    if any(token in text for token in ["policy", "approval", "allow", "deny", "control"]):
        return "policy"
    return "evidence"


def _agent_owner_index(evidence: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, str]:
    owners: dict[str, str] = {}
    for agent in (evidence.get("agents") or {}).get("agents", []) or []:
        if isinstance(agent, dict) and agent.get("id") and agent.get("owner"):
            owners[str(agent["id"])] = str(agent["owner"])
    for finding in findings:
        context = finding.get("operational_context") or {}
        owner = _string(context.get("owner"))
        agent = _string(context.get("agent_id"))
        if agent and owner:
            owners.setdefault(agent, owner)
        for node in finding.get("nodes", []) or []:
            node_text = _string(node)
            if node_text.startswith("agent:") and owner:
                owners.setdefault(node_text.split(":", 1)[1], owner)
    return owners


def _finding_index(findings: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    by_id = {str(finding.get("id", "")): finding for finding in findings if finding.get("id")}
    by_gap: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        for gap_id in finding.get("visibility_gaps", []) or []:
            by_gap[str(gap_id)].append(finding)
    return by_id, by_gap


def _owner_for_related(
    owner: str,
    agent: str,
    agent_owners: dict[str, str],
    related_findings: list[dict[str, Any]],
) -> str:
    if owner:
        return owner
    if agent and agent_owners.get(agent):
        return agent_owners[agent]
    for finding in related_findings:
        context = finding.get("operational_context") or {}
        if context.get("owner"):
            return str(context["owner"])
    return "unassigned"


def _finding_target(finding: dict[str, Any]) -> str:
    context = finding.get("operational_context") or {}
    for key in ["target_system", "approval_policy", "runtime", "environment"]:
        if context.get(key):
            return str(context[key])
    for item in finding.get("path", []) or []:
        text = _string(item)
        if text.startswith("tool:"):
            return text.split(":", 1)[1]
    return _string(finding.get("title"), "finding")


def _next_command_from_action(action: str) -> str:
    if not action:
        return ""
    lowered = action.lower()
    if "agentguard-graph" in lowered:
        return action
    if "re-run" in lowered or "rerun" in lowered:
        return "agentguard-graph scan --evidence-dir agent-evidence/ --out outputs/agent-risk.json --markdown outputs/agent-risk.md --html outputs/agent-risk.html"
    if "evidence" in lowered or "export" in lowered or "provide" in lowered:
        return "agentguard-graph validate --evidence-dir agent-evidence/ --json"
    if "policy" in lowered or "approval" in lowered or "control" in lowered:
        return "agentguard-graph scan --evidence-dir agent-evidence/ --out outputs/agent-risk.json --markdown outputs/agent-risk.md --html outputs/agent-risk.html"
    return ""


def _make_action(
    actions: list[dict[str, Any]],
    seen: set[tuple[str, str, str, str]],
    *,
    priority: str,
    owner: str,
    target: str,
    category: str,
    reason: str,
    source: str,
    suggested_next_command: str = "",
    requested_evidence: str = "",
    related_finding_ids: list[str] | None = None,
    related_gap_ids: list[str] | None = None,
) -> None:
    priority = priority if priority in _PRIORITY_RANK else "P2"
    owner = _string(owner, "unassigned")
    target = _string(target, "unknown")
    category = _string(category, "evidence")
    reason = _string(reason, "Review the related offline evidence.")
    key = (owner, target, category, reason)
    if key in seen:
        return
    seen.add(key)
    related_finding_ids = _strings(related_finding_ids or [])
    related_gap_ids = _strings(related_gap_ids or [])
    seed = {
        "owner": owner,
        "target": target,
        "category": category,
        "reason": reason,
        "related_finding_ids": related_finding_ids,
        "related_gap_ids": related_gap_ids,
    }
    action: dict[str, Any] = {
        "id": _stable_id(seed),
        "priority": priority,
        "owner": owner,
        "target": target,
        "category": category,
        "reason": reason,
        "related_finding_ids": related_finding_ids,
        "related_gap_ids": related_gap_ids,
        "source": source,
    }
    if suggested_next_command:
        action["suggested_next_command"] = suggested_next_command
    action["requested_evidence"] = requested_evidence or "Review related offline evidence and rerun the scan."
    actions.append(action)


def _rollups(actions: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for action in actions:
        buckets[_string(action.get(field), "unknown")].append(action)
    rows = []
    for value, items in buckets.items():
        priority_counts = Counter(str(item.get("priority", "P2")) for item in items)
        rows.append(
            {
                field: value,
                "action_count": len(items),
                "p1": priority_counts.get("P1", 0),
                "p2": priority_counts.get("P2", 0),
                "p3": priority_counts.get("P3", 0),
                "action_ids": [str(item["id"]) for item in items],
            }
        )
    return sorted(rows, key=lambda row: (-int(row["p1"]), -int(row["action_count"]), str(row[field])))


def build_remediation_plan(
    evidence: dict[str, Any],
    *,
    findings: list[dict[str, Any]],
    visibility_gaps: list[dict[str, Any]],
    offline_control_analysis: dict[str, Any],
    policy_analysis: dict[str, Any],
    iam_analysis: dict[str, Any],
    privacy_analysis: dict[str, Any],
    evidence_guide: dict[str, Any],
) -> dict[str, Any]:
    """Build a bounded offline action plan from existing report evidence."""

    actions: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    agent_owners = _agent_owner_index(evidence, findings)
    findings_by_id, findings_by_gap = _finding_index(findings)

    for finding in findings:
        if finding.get("risk_status") == "accepted" and finding.get("tier") not in {"urgent", "high"}:
            continue
        remediation = finding.get("remediation") or {}
        next_items = (
            remediation.get("validation_steps")
            or remediation.get("recommended_controls")
            or finding.get("recommendations")
            or finding.get("recommended_next_evidence")
            or []
        )
        next_item = _string(next_items[0] if next_items else "")
        context = finding.get("operational_context") or {}
        category = _category_from_text(finding.get("rule_id"), finding.get("title"), " ".join(finding.get("visibility_gaps", [])))
        _make_action(
            actions,
            seen,
            priority=_TIER_PRIORITY.get(str(finding.get("tier", "medium")), "P2"),
            owner=_owner_for_related(_string(context.get("owner")), _string(context.get("agent_id")), agent_owners, [finding]),
            target=_finding_target(finding),
            category=category,
            reason=f"Address {finding.get('tier', 'medium')} finding: {finding.get('title', 'unknown')}",
            source="finding",
            suggested_next_command=_next_command_from_action(next_item),
            requested_evidence="; ".join(_strings(finding.get("recommended_next_evidence", []))),
            related_finding_ids=[str(finding.get("id", ""))],
            related_gap_ids=_strings(finding.get("visibility_gaps", [])),
        )

    for gap in visibility_gaps:
        gap_id = _string(gap.get("id"))
        related = [findings_by_id[item] for item in gap.get("affected_findings", []) or [] if item in findings_by_id]
        if not related:
            related = findings_by_gap.get(gap_id, [])
        _make_action(
            actions,
            seen,
            priority=_GAP_PRIORITY.get(str(gap.get("priority", "medium_gap")), "P2"),
            owner=_owner_for_related("", _string(gap.get("agent")), agent_owners, related),
            target=_string(gap.get("target"), "unknown"),
            category=_category_from_text(gap.get("type"), gap.get("reason"), gap.get("requested_evidence")),
            reason=_string(gap.get("reason"), f"Resolve visibility gap {gap_id or 'unknown'}."),
            source="visibility_gap",
            requested_evidence=_string(gap.get("requested_evidence")),
            related_finding_ids=[str(item.get("id", "")) for item in related],
            related_gap_ids=[gap_id],
        )

    for gap in offline_control_analysis.get("policy_control_gaps", []) or []:
        agent = _string(gap.get("agent"))
        missing_controls = ", ".join(_strings(gap.get("missing_controls", [])))
        _make_action(
            actions,
            seen,
            priority="P1" if {"approval_required", "audit_logging"} & set(_strings(gap.get("missing_controls", []))) else "P2",
            owner=_owner_for_related("", agent, agent_owners, []),
            target=_string(gap.get("target_system")) or _string(gap.get("tool"), "unknown"),
            category=_category_from_text(missing_controls, "policy control"),
            reason=_string(gap.get("reason"), f"Missing required controls: {missing_controls}"),
            source="offline_control_analysis.policy_control_gaps",
            requested_evidence=_string(gap.get("requested_evidence")),
            related_gap_ids=[_string(gap.get("id"))],
        )

    for gap in policy_analysis.get("gaps", []) or []:
        _make_action(
            actions,
            seen,
            priority="P2",
            owner="policy",
            target=_string(gap.get("target"), "policy"),
            category="policy",
            reason=_string(gap.get("reason") or gap.get("repair"), "Resolve policy evaluation gap."),
            source="policy_analysis.gaps",
            suggested_next_command=_next_command_from_action(_string(gap.get("repair"))),
            requested_evidence=_string(gap.get("requested_evidence")),
            related_gap_ids=[_string(gap.get("id"))],
        )

    for risk in policy_analysis.get("rule_risks", []) or []:
        agent = _string(risk.get("agent"))
        _make_action(
            actions,
            seen,
            priority="P1" if risk.get("effective_decision") == "allow" else "P2",
            owner=_owner_for_related("policy", agent, agent_owners, []),
            target=_string(risk.get("target_system")) or _string(risk.get("tool"), "policy"),
            category="policy",
            reason=_string(risk.get("reason"), "Review risky policy rule."),
            source="policy_analysis.rule_risks",
            suggested_next_command=_next_command_from_action(_string(risk.get("repair"))),
        )

    for item in iam_analysis.get("least_privilege_suggestions", []) or []:
        _make_action(
            actions,
            seen,
            priority=_string(item.get("priority"), "P2"),
            owner="identity",
            target=_string(item.get("target_system")) or _string(item.get("identity")) or _string(item.get("tool"), "identity"),
            category="identity",
            reason=_string(item.get("suggestion"), "Apply least-privilege suggestion."),
            source="iam_analysis.least_privilege_suggestions",
            suggested_next_command="agentguard-graph validate --evidence-dir agent-evidence/ --json",
        )

    for item in iam_analysis.get("unused_identities", []) or []:
        _make_action(
            actions,
            seen,
            priority="P2",
            owner="identity",
            target=_string(item.get("identity"), "identity"),
            category="identity",
            reason=_string(item.get("reason"), "Review unused identity."),
            source="iam_analysis.unused_identities",
            requested_evidence="Current identity ownership and permission export.",
        )

    for item in iam_analysis.get("unused_permissions", []) or []:
        _make_action(
            actions,
            seen,
            priority="P2",
            owner="identity",
            target=_string(item.get("resource")) or _string(item.get("identity"), "permission"),
            category="identity",
            reason=_string(item.get("reason"), "Remove or justify unused permissions."),
            source="iam_analysis.unused_permissions",
            requested_evidence="Current permission export after privilege review.",
        )

    for item in privacy_analysis.get("classification_gaps", []) or []:
        _make_action(
            actions,
            seen,
            priority="P1",
            owner="privacy",
            target=_string(item.get("target"), "data classification"),
            category="data_protection",
            reason=_string(item.get("reason"), "Classify data source used by agent tooling."),
            source="privacy_analysis.classification_gaps",
            requested_evidence=_string(item.get("requested_evidence"), "Data catalog classification export."),
            related_gap_ids=[_string(item.get("id"))],
        )

    for item in privacy_analysis.get("memory_retention", []) or []:
        status = _string(item.get("status"))
        if status in {"complete", "documented"}:
            continue
        _make_action(
            actions,
            seen,
            priority="P2",
            owner=_string(item.get("owner"), "privacy"),
            target=_string(item.get("id"), "memory retention"),
            category="data_protection",
            reason="Document retention period, deletion policy, and data classes for memory storage.",
            source="privacy_analysis.memory_retention",
            requested_evidence="Memory retention and deletion policy evidence.",
        )

    existing_gap_ids = {str(action_gap) for action in actions for action_gap in action.get("related_gap_ids", [])}
    for item in evidence_guide.get("top_missing_evidence", []) or []:
        gap_id = _string(item.get("id"))
        if gap_id and gap_id in existing_gap_ids:
            continue
        related = [findings_by_id[finding_id] for finding_id in item.get("affected_findings", []) or [] if finding_id in findings_by_id]
        _make_action(
            actions,
            seen,
            priority=_GAP_PRIORITY.get(str(item.get("priority", "medium_gap")), "P2"),
            owner=_owner_for_related("", "", agent_owners, related),
            target=_string(item.get("target"), "evidence"),
            category=_category_from_text(item.get("type"), item.get("requested_evidence")),
            reason=_string(item.get("reason"), "Collect missing evidence requested by evidence guide."),
            source="evidence_guide.top_missing_evidence",
            requested_evidence=_string(item.get("requested_evidence")),
            related_finding_ids=[str(finding.get("id", "")) for finding in related],
            related_gap_ids=[gap_id],
        )

    actions.sort(
        key=lambda item: (
            _PRIORITY_RANK.get(str(item.get("priority", "P2")), 1),
            str(item.get("owner", "")),
            str(item.get("category", "")),
            str(item.get("target", "")),
            str(item.get("id", "")),
        )
    )
    by_priority = Counter(str(action.get("priority", "P2")) for action in actions)
    by_owner = Counter(str(action.get("owner", "unassigned")) for action in actions)
    by_category = Counter(str(action.get("category", "evidence")) for action in actions)
    by_system = Counter(str(action.get("target", "unknown")) for action in actions)
    return {
        "summary": {
            "actions": len(actions),
            "p1": by_priority.get("P1", 0),
            "p2": by_priority.get("P2", 0),
            "p3": by_priority.get("P3", 0),
            "owners": len(by_owner),
            "systems": len(by_system),
            "categories": len(by_category),
            "by_owner": dict(sorted(by_owner.items())),
            "by_system": dict(sorted(by_system.items())),
            "by_category": dict(sorted(by_category.items())),
        },
        "owner_rollups": _rollups(actions, "owner"),
        "system_rollups": _rollups(actions, "target"),
        "category_rollups": _rollups(actions, "category"),
        "actions": actions,
    }
