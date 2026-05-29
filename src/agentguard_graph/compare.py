"""Report comparison helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import __version__
from .errors import EvidenceLoadError


TIER_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "urgent": 4}
MATERIAL_FINDING_FIELDS = [
    "tier",
    "score",
    "path_state",
    "evidence_quality",
    "observation_status",
    "risk_status",
    "accepted_risk",
    "visibility_gap_priorities",
]


def load_compare_report(path: str | Path) -> dict[str, Any]:
    report_path = Path(path)
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceLoadError(f"{report_path}: cannot read report: {exc}") from exc
    if not isinstance(report, dict):
        raise EvidenceLoadError(f"{report_path}: report must be a JSON object")
    for field in ["findings", "attack_paths", "visibility_gaps"]:
        if field in report and not isinstance(report[field], list):
            raise EvidenceLoadError(f"{report_path}: {field} must be a list")
    return report


def compare_reports(
    base_report: dict[str, Any],
    head_report: dict[str, Any],
    *,
    base_label: str = "base",
    head_label: str = "head",
    base_source_type: str = "report",
    head_source_type: str = "report",
) -> dict[str, Any]:
    base_findings = _items_by_id(base_report.get("findings", []))
    head_findings = _items_by_id(head_report.get("findings", []))
    base_paths = _items_by_id(base_report.get("attack_paths", []))
    head_paths = _items_by_id(head_report.get("attack_paths", []))
    base_gaps = _items_by_id(base_report.get("visibility_gaps", []))
    head_gaps = _items_by_id(head_report.get("visibility_gaps", []))
    evidence_manifest_drift = _evidence_manifest_drift(
        base_report.get("evidence_manifest"),
        head_report.get("evidence_manifest"),
    )
    remediation_plan_drift = _remediation_plan_drift(
        base_report.get("remediation_plan"),
        head_report.get("remediation_plan"),
    )

    new_findings = [_finding_summary(head_findings[item_id], "new") for item_id in sorted(head_findings.keys() - base_findings.keys())]
    resolved_findings = [
        _finding_summary(base_findings[item_id], "resolved") for item_id in sorted(base_findings.keys() - head_findings.keys())
    ]
    changed_findings: list[dict[str, Any]] = []
    unchanged_findings: list[dict[str, Any]] = []
    for item_id in sorted(base_findings.keys() & head_findings.keys()):
        base = base_findings[item_id]
        head = head_findings[item_id]
        changes = _material_changes(base, head, MATERIAL_FINDING_FIELDS)
        status = _change_status(base, head, changes)
        entry = {
            "id": item_id,
            "status": status,
            "title": str(head.get("title") or base.get("title") or item_id),
            "base": _finding_summary(base, "base"),
            "head": _finding_summary(head, "head"),
            "changes": changes,
        }
        if changes:
            changed_findings.append(entry)
        else:
            unchanged_findings.append(entry)

    new_gaps = [_gap_summary(head_gaps[item_id], "new") for item_id in sorted(head_gaps.keys() - base_gaps.keys())]
    resolved_gaps = [_gap_summary(base_gaps[item_id], "resolved") for item_id in sorted(base_gaps.keys() - head_gaps.keys())]
    unchanged_gaps = [_gap_summary(head_gaps[item_id], "unchanged") for item_id in sorted(base_gaps.keys() & head_gaps.keys())]

    summary = {
        "base_findings": len(base_findings),
        "head_findings": len(head_findings),
        "new_findings": len(new_findings),
        "resolved_findings": len(resolved_findings),
        "changed_findings": len(changed_findings),
        "unchanged_findings": len(unchanged_findings),
        "improved_findings": sum(1 for item in changed_findings if item["status"] == "improved"),
        "regressed_findings": sum(1 for item in changed_findings if item["status"] == "regressed"),
        "base_urgent": _count_tier(base_findings.values(), "urgent"),
        "head_urgent": _count_tier(head_findings.values(), "urgent"),
        "base_high": _count_tier(base_findings.values(), "high"),
        "head_high": _count_tier(head_findings.values(), "high"),
        "base_accepted_risk_findings": _count_risk_status(base_findings.values(), "accepted"),
        "head_accepted_risk_findings": _count_risk_status(head_findings.values(), "accepted"),
        "base_expired_accepted_risk_findings": _count_risk_status(base_findings.values(), "acceptance_expired"),
        "head_expired_accepted_risk_findings": _count_risk_status(head_findings.values(), "acceptance_expired"),
        "new_high_or_urgent": _count_high_or_urgent(new_findings),
        "resolved_high_or_urgent": _count_high_or_urgent(resolved_findings),
        "base_attack_paths": len(base_paths),
        "head_attack_paths": len(head_paths),
        "new_attack_paths": len(head_paths.keys() - base_paths.keys()),
        "resolved_attack_paths": len(base_paths.keys() - head_paths.keys()),
        "base_visibility_gaps": len(base_gaps),
        "head_visibility_gaps": len(head_gaps),
        "new_visibility_gaps": len(new_gaps),
        "resolved_visibility_gaps": len(resolved_gaps),
        "base_evidence_manifest_status": evidence_manifest_drift["base"]["status"],
        "head_evidence_manifest_status": evidence_manifest_drift["head"]["status"],
        "evidence_manifest_status_changed": evidence_manifest_drift["status_changed"],
        "evidence_manifest_checked_delta": evidence_manifest_drift["deltas"]["checked_count"],
        "evidence_manifest_changed_delta": evidence_manifest_drift["deltas"]["changed_count"],
        "evidence_manifest_missing_delta": evidence_manifest_drift["deltas"]["missing_count"],
        "evidence_manifest_unmanifested_delta": evidence_manifest_drift["deltas"]["unmanifested_count"],
        "evidence_manifest_errors_delta": evidence_manifest_drift["deltas"]["errors_count"],
        "base_remediation_actions": remediation_plan_drift["base"]["actions"],
        "head_remediation_actions": remediation_plan_drift["head"]["actions"],
        "remediation_actions_delta": remediation_plan_drift["deltas"]["actions"],
        "remediation_p1_delta": remediation_plan_drift["deltas"]["p1"],
        "remediation_p2_delta": remediation_plan_drift["deltas"]["p2"],
        "remediation_p3_delta": remediation_plan_drift["deltas"]["p3"],
        "new_remediation_actions": len(remediation_plan_drift["new_action_ids"]),
        "resolved_remediation_actions": len(remediation_plan_drift["resolved_action_ids"]),
    }

    return {
        "schema_version": "0.1",
        "tool": {"name": "agentguard-graph", "version": __version__},
        "compare": {
            "base": {"label": base_label, "source_type": base_source_type, "summary": base_report.get("summary", {})},
            "head": {"label": head_label, "source_type": head_source_type, "summary": head_report.get("summary", {})},
        },
        "summary": summary,
        "review": _review_delta(summary, new_findings, resolved_findings, changed_findings, new_gaps),
        "findings": {
            "new": new_findings,
            "resolved": resolved_findings,
            "changed": changed_findings,
            "unchanged": [{"id": item["id"], "title": item["title"], "status": "unchanged"} for item in unchanged_findings],
        },
        "visibility_gaps": {
            "new": new_gaps,
            "resolved": resolved_gaps,
            "unchanged": unchanged_gaps,
        },
        "evidence_manifest": evidence_manifest_drift,
        "remediation_plan": remediation_plan_drift,
        "attack_paths": {
            "new": [_path_summary(head_paths[item_id], "new") for item_id in sorted(head_paths.keys() - base_paths.keys())],
            "resolved": [
                _path_summary(base_paths[item_id], "resolved") for item_id in sorted(base_paths.keys() - head_paths.keys())
            ],
        },
    }


def write_compare_markdown(compare_report: dict[str, Any], path: str | Path) -> None:
    output_path = Path(path)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(render_compare_markdown(compare_report), encoding="utf-8")
    except OSError as exc:
        raise EvidenceLoadError(f"{output_path}: cannot write Markdown compare report: {exc}") from exc


def render_compare_markdown(compare_report: dict[str, Any]) -> str:
    summary = compare_report.get("summary", {})
    compare = compare_report.get("compare", {})
    review = compare_report.get("review", {})
    findings = compare_report.get("findings", {})
    gaps = compare_report.get("visibility_gaps", {})
    manifest = compare_report.get("evidence_manifest", {})
    remediation = compare_report.get("remediation_plan", {})
    base_label = _md(str((compare.get("base") or {}).get("label", "base")))
    head_label = _md(str((compare.get("head") or {}).get("label", "head")))

    lines = [
        "# AgentGuard Graph Compare",
        "",
        f"- Base: {base_label}",
        f"- Head: {head_label}",
        f"- Decision: {_md(str(review.get('decision', 'unknown')))}",
        f"- Label: {_md(str(review.get('label', '')))}",
        f"- Findings: {summary.get('base_findings', 0)} -> {summary.get('head_findings', 0)}",
        f"- New / resolved: {summary.get('new_findings', 0)} / {summary.get('resolved_findings', 0)}",
        f"- Improved / regressed: {summary.get('improved_findings', 0)} / {summary.get('regressed_findings', 0)}",
        f"- Visibility gaps: {summary.get('base_visibility_gaps', 0)} -> {summary.get('head_visibility_gaps', 0)}",
        f"- Accepted risk: {summary.get('base_accepted_risk_findings', 0)} -> {summary.get('head_accepted_risk_findings', 0)}",
        f"- Expired accepted risk: {summary.get('base_expired_accepted_risk_findings', 0)} -> {summary.get('head_expired_accepted_risk_findings', 0)}",
        "",
        "## Evidence Manifest Drift",
        "",
    ]
    _append_manifest_drift(lines, manifest)
    lines.extend(
        [
            "",
            "## Remediation Plan Drift",
            "",
        ]
    )
    _append_remediation_drift(lines, remediation)
    lines.extend(
        [
            "",
            "## Required Actions",
            "",
        ]
    )
    for action in review.get("required_actions", []) or ["No required actions."]:
        lines.append(f"- {_md(str(action))}")
    lines.extend(["", "## New Findings", ""])
    _append_finding_list(lines, findings.get("new", []))
    lines.extend(["", "## Regressed Findings", ""])
    _append_changed_list(lines, [item for item in findings.get("changed", []) if item.get("status") == "regressed"])
    lines.extend(["", "## Improved Findings", ""])
    _append_changed_list(lines, [item for item in findings.get("changed", []) if item.get("status") == "improved"])
    lines.extend(["", "## Other Changed Findings", ""])
    _append_changed_list(lines, [item for item in findings.get("changed", []) if item.get("status") == "changed"])
    lines.extend(["", "## Resolved Findings", ""])
    _append_finding_list(lines, findings.get("resolved", []))
    lines.extend(["", "## New Visibility Gaps", ""])
    if gaps.get("new"):
        for gap in gaps["new"]:
            lines.append(
                f"- `{_md(str(gap.get('id', '')))}` "
                f"{_md(str(gap.get('priority', '')))}: {_md(str(gap.get('target', '')))}"
            )
    else:
        lines.append("None.")
    lines.append("")
    return "\n".join(lines)


def _append_manifest_drift(lines: list[str], manifest: dict[str, Any]) -> None:
    if not manifest:
        lines.append("No evidence manifest drift summary recorded.")
        return
    base = manifest.get("base", {})
    head = manifest.get("head", {})
    deltas = manifest.get("deltas", {})
    lines.extend(
        [
            f"- Status: {_md(str(base.get('status', 'not_provided')))} -> {_md(str(head.get('status', 'not_provided')))}",
            f"- Checked files: {base.get('checked_count', 0)} -> {head.get('checked_count', 0)} ({_signed(deltas.get('checked_count', 0))})",
            f"- Changed files: {base.get('changed_count', 0)} -> {head.get('changed_count', 0)} ({_signed(deltas.get('changed_count', 0))})",
            f"- Missing files: {base.get('missing_count', 0)} -> {head.get('missing_count', 0)} ({_signed(deltas.get('missing_count', 0))})",
            f"- Unmanifested files: {base.get('unmanifested_count', 0)} -> {head.get('unmanifested_count', 0)} ({_signed(deltas.get('unmanifested_count', 0))})",
            f"- Errors: {base.get('errors_count', 0)} -> {head.get('errors_count', 0)} ({_signed(deltas.get('errors_count', 0))})",
        ]
    )


def _append_remediation_drift(lines: list[str], remediation: dict[str, Any]) -> None:
    if not remediation:
        lines.append("No remediation plan drift summary recorded.")
        return
    base = remediation.get("base", {})
    head = remediation.get("head", {})
    deltas = remediation.get("deltas", {})
    lines.extend(
        [
            f"- Actions: {base.get('actions', 0)} -> {head.get('actions', 0)} ({_signed(deltas.get('actions', 0))})",
            f"- P1 / P2 / P3 deltas: {_signed(deltas.get('p1', 0))} / {_signed(deltas.get('p2', 0))} / {_signed(deltas.get('p3', 0))}",
            f"- New / resolved action ids: {len(remediation.get('new_action_ids', []))} / {len(remediation.get('resolved_action_ids', []))}",
        ]
    )
    _append_count_changes(lines, "Owner changes", remediation.get("owner_count_changes", {}))
    _append_count_changes(lines, "System changes", remediation.get("system_count_changes", {}))
    _append_count_changes(lines, "Category changes", remediation.get("category_count_changes", {}))


def _append_count_changes(lines: list[str], label: str, changes: dict[str, Any]) -> None:
    if not changes:
        lines.append(f"- {label}: none.")
        return
    rows = []
    for key in sorted(changes):
        value = changes[key]
        if not isinstance(value, dict):
            continue
        rows.append(
            f"{_md(str(key))} {value.get('base', 0)}->{value.get('head', 0)} ({_signed(value.get('delta', 0))})"
        )
    lines.append(f"- {label}: " + ("; ".join(rows[:8]) if rows else "none."))


def _append_finding_list(lines: list[str], findings: list[dict[str, Any]]) -> None:
    if not findings:
        lines.append("None.")
        return
    for finding in findings:
        lines.append(
            f"- `{_md(str(finding.get('id', '')))}` "
            f"{_md(str(finding.get('tier', 'unknown')))} "
            f"score={finding.get('score', 0)} "
            f"risk_status={_md(str(finding.get('risk_status', 'open')))}: {_md(str(finding.get('title', '')))}"
        )


def _append_changed_list(lines: list[str], findings: list[dict[str, Any]]) -> None:
    if not findings:
        lines.append("None.")
        return
    for item in findings:
        base = item.get("base", {})
        head = item.get("head", {})
        lines.append(
            f"- `{_md(str(item.get('id', '')))}` "
            f"{_md(str(base.get('tier', 'unknown')))}:{base.get('score', 0)} -> "
            f"{_md(str(head.get('tier', 'unknown')))}:{head.get('score', 0)} "
            f"risk_status={_md(str(base.get('risk_status', 'open')))}->{_md(str(head.get('risk_status', 'open')))} "
            f"{_md(str(item.get('title', '')))}"
        )


def _items_by_id(items: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list):
        return {}
    return {str(item["id"]): item for item in items if isinstance(item, dict) and item.get("id")}


def _material_changes(base: dict[str, Any], head: dict[str, Any], fields: list[str]) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for field in fields:
        if base.get(field) != head.get(field):
            changes.append({"field": field, "base": base.get(field), "head": head.get(field)})
    return changes


def _change_status(base: dict[str, Any], head: dict[str, Any], changes: list[dict[str, Any]]) -> str:
    if not changes:
        return "unchanged"
    base_rank = _severity_tuple(base)
    head_rank = _severity_tuple(head)
    if head_rank > base_rank:
        return "regressed"
    if head_rank < base_rank:
        return "improved"
    return "changed"


def _severity_tuple(item: dict[str, Any]) -> tuple[int, int]:
    return (TIER_RANK.get(str(item.get("tier", "unknown")), 0), _int(item.get("score", 0)))


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _count_tier(items: Any, tier: str) -> int:
    return sum(1 for item in items if isinstance(item, dict) and item.get("tier") == tier)


def _count_risk_status(items: Any, risk_status: str) -> int:
    return sum(1 for item in items if isinstance(item, dict) and item.get("risk_status") == risk_status)


def _count_high_or_urgent(items: list[dict[str, Any]]) -> int:
    return sum(1 for item in items if item.get("tier") in {"high", "urgent"})


def _finding_summary(item: dict[str, Any], status: str) -> dict[str, Any]:
    context = item.get("operational_context") or {}
    return {
        "id": str(item.get("id", "")),
        "status": status,
        "title": str(item.get("title", "")),
        "type": str(item.get("type", "")),
        "tier": str(item.get("tier", "unknown")),
        "score": _int(item.get("score", 0)),
        "path_state": str(item.get("path_state", "")),
        "evidence_quality": str(item.get("evidence_quality", "")),
        "observation_status": str(item.get("observation_status", "")),
        "risk_status": str(item.get("risk_status", "open")),
        "accepted_risk": item.get("accepted_risk", {}) if isinstance(item.get("accepted_risk", {}), dict) else {},
        "owner": context.get("owner"),
        "environment": context.get("environment"),
        "visibility_gaps": item.get("visibility_gaps", []) if isinstance(item.get("visibility_gaps", []), list) else [],
        "visibility_gap_priorities": item.get("visibility_gap_priorities", [])
        if isinstance(item.get("visibility_gap_priorities", []), list)
        else [],
    }


def _gap_summary(item: dict[str, Any], status: str) -> dict[str, Any]:
    return {
        "id": str(item.get("id", "")),
        "status": status,
        "priority": str(item.get("priority", "")),
        "type": str(item.get("type", "")),
        "target": str(item.get("target", "")),
        "reason": str(item.get("reason", "")),
        "requested_evidence": str(item.get("requested_evidence", "")),
        "affected_findings": item.get("affected_findings", []) if isinstance(item.get("affected_findings", []), list) else [],
    }


def _path_summary(item: dict[str, Any], status: str) -> dict[str, Any]:
    return {
        "id": str(item.get("id", "")),
        "status": status,
        "rule_id": str(item.get("rule_id", "")),
        "title": str(item.get("title", "")),
        "tier": str(item.get("tier", "unknown")),
        "score": _int(item.get("score", 0)),
        "path_state": str(item.get("path_state", "")),
        "evidence_quality": str(item.get("evidence_quality", "")),
        "risk_status": str(item.get("risk_status", "open")),
        "accepted_risk": item.get("accepted_risk", {}) if isinstance(item.get("accepted_risk", {}), dict) else {},
    }


def _evidence_manifest_drift(base_manifest: Any, head_manifest: Any) -> dict[str, Any]:
    base = _manifest_summary(base_manifest)
    head = _manifest_summary(head_manifest)
    deltas = {field: head[field] - base[field] for field in _manifest_count_fields()}
    return {
        "base": base,
        "head": head,
        "deltas": deltas,
        "status_changed": base["status"] != head["status"],
        "has_drift": base["status"] != head["status"] or any(value != 0 for value in deltas.values()),
    }


def _manifest_summary(manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        manifest = {}
    summary = manifest.get("summary") if isinstance(manifest.get("summary"), dict) else {}
    return {
        "status": str(manifest.get("status") or "not_provided"),
        "checked_count": _int(summary.get("checked_count", 0)),
        "changed_count": _int(summary.get("changed_count", 0)),
        "missing_count": _int(summary.get("missing_count", 0)),
        "unmanifested_count": _int(summary.get("unmanifested_count", 0)),
        "errors_count": len(manifest.get("errors", [])) if isinstance(manifest.get("errors"), list) else 0,
    }


def _manifest_count_fields() -> list[str]:
    return ["checked_count", "changed_count", "missing_count", "unmanifested_count", "errors_count"]


def _remediation_plan_drift(base_plan: Any, head_plan: Any) -> dict[str, Any]:
    base = _remediation_summary(base_plan)
    head = _remediation_summary(head_plan)
    count_fields = ["actions", "p1", "p2", "p3", "owners", "systems", "categories"]
    base_action_ids = _remediation_action_ids(base_plan)
    head_action_ids = _remediation_action_ids(head_plan)
    return {
        "base": {field: base[field] for field in count_fields},
        "head": {field: head[field] for field in count_fields},
        "deltas": {field: head[field] - base[field] for field in count_fields},
        "new_action_ids": sorted(head_action_ids - base_action_ids),
        "resolved_action_ids": sorted(base_action_ids - head_action_ids),
        "owner_count_changes": _count_map_changes(base["by_owner"], head["by_owner"]),
        "system_count_changes": _count_map_changes(base["by_system"], head["by_system"]),
        "category_count_changes": _count_map_changes(base["by_category"], head["by_category"]),
    }


def _remediation_summary(plan: Any) -> dict[str, Any]:
    if not isinstance(plan, dict):
        plan = {}
    summary = plan.get("summary") if isinstance(plan.get("summary"), dict) else {}
    actions = plan.get("actions", []) if isinstance(plan.get("actions"), list) else []
    by_owner = _count_map(summary.get("by_owner"))
    by_system = _count_map(summary.get("by_system"))
    by_category = _count_map(summary.get("by_category"))
    if not by_owner:
        by_owner = _rollup_count_map(plan.get("owner_rollups"), "owner")
    if not by_system:
        by_system = _rollup_count_map(plan.get("system_rollups"), "target")
    if not by_category:
        by_category = _rollup_count_map(plan.get("category_rollups"), "category")
    return {
        "actions": _int(summary.get("actions", len(actions))),
        "p1": _int(summary.get("p1", _priority_count(actions, "P1"))),
        "p2": _int(summary.get("p2", _priority_count(actions, "P2"))),
        "p3": _int(summary.get("p3", _priority_count(actions, "P3"))),
        "owners": _int(summary.get("owners", len(by_owner))),
        "systems": _int(summary.get("systems", len(by_system))),
        "categories": _int(summary.get("categories", len(by_category))),
        "by_owner": by_owner,
        "by_system": by_system,
        "by_category": by_category,
    }


def _remediation_action_ids(plan: Any) -> set[str]:
    if not isinstance(plan, dict) or not isinstance(plan.get("actions"), list):
        return set()
    return {str(action["id"]) for action in plan["actions"] if isinstance(action, dict) and action.get("id")}


def _priority_count(actions: list[Any], priority: str) -> int:
    return sum(1 for action in actions if isinstance(action, dict) and action.get("priority") == priority)


def _count_map(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    return {str(key): _int(count) for key, count in sorted(value.items(), key=lambda item: str(item[0]))}


def _rollup_count_map(rows: Any, key_field: str) -> dict[str, int]:
    if not isinstance(rows, list):
        return {}
    result: dict[str, int] = {}
    for row in rows:
        if isinstance(row, dict) and row.get(key_field):
            result[str(row[key_field])] = _int(row.get("action_count", 0))
    return dict(sorted(result.items()))


def _count_map_changes(base: dict[str, int], head: dict[str, int]) -> dict[str, dict[str, int]]:
    changes = {}
    for key in sorted(set(base) | set(head)):
        base_count = base.get(key, 0)
        head_count = head.get(key, 0)
        if base_count != head_count:
            changes[key] = {"base": base_count, "head": head_count, "delta": head_count - base_count}
    return changes


def _review_delta(
    summary: dict[str, int],
    new_findings: list[dict[str, Any]],
    resolved_findings: list[dict[str, Any]],
    changed_findings: list[dict[str, Any]],
    new_gaps: list[dict[str, Any]],
) -> dict[str, Any]:
    regressed = [item for item in changed_findings if item.get("status") == "regressed"]
    improved = [item for item in changed_findings if item.get("status") == "improved"]
    neutral_changes = [item for item in changed_findings if item.get("status") == "changed"]
    new_high = [item for item in new_findings if item.get("tier") in {"urgent", "high"}]
    new_critical_gaps = [item for item in new_gaps if item.get("priority") in {"critical_gap", "high_gap"}]
    expired_acceptances = summary.get("head_expired_accepted_risk_findings", 0)
    if expired_acceptances:
        return {
            "decision": "changed",
            "label": "Review expired accepted risk",
            "reason": "The head report contains expired accepted-risk metadata.",
            "required_actions": [
                "Renew, revoke, or close expired accepted-risk records.",
                "Review affected findings before approval.",
            ],
        }
    if regressed or new_high or new_critical_gaps:
        return {
            "decision": "regressed",
            "label": "Review regressed findings",
            "reason": "The head report introduced high-impact findings, higher-severity findings, or high-priority gaps.",
            "required_actions": [
                "Review new and regressed findings before approval.",
                "Assign owners for new high-priority visibility gaps.",
                "Re-run compare after remediation evidence is added.",
            ],
        }
    if improved or resolved_findings:
        return {
            "decision": "improved",
            "label": "Risk posture improved",
            "reason": "The head report resolved findings or reduced finding severity without new high-impact regressions.",
            "required_actions": [
                "Confirm resolved findings match intentional remediation.",
                "Keep the comparison report with the review record.",
            ],
        }
    if summary.get("new_findings") or neutral_changes or summary.get("resolved_visibility_gaps") or summary.get("new_visibility_gaps"):
        return {
            "decision": "changed",
            "label": "Review changed evidence",
            "reason": "The reports differ, but no high-impact regression was detected.",
            "required_actions": ["Review the changed findings and visibility gaps."],
        }
    return {
        "decision": "unchanged",
        "label": "No material change",
        "reason": "The compared findings and visibility gaps are materially unchanged.",
        "required_actions": ["Continue periodic evidence refresh."],
    }


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _signed(value: Any) -> str:
    number = _int(value)
    if number > 0:
        return f"+{number}"
    return str(number)
