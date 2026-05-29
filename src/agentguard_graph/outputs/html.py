"""Self-contained HTML report writer."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from ..errors import EvidenceLoadError
from ..privacy_analysis import privacy_filter_tokens_for_text


def h(value: object) -> str:
    return html.escape(str(value), quote=True)


def _badge(label: str, class_name: str = "") -> str:
    return f'<span class="badge {h(class_name)}">{h(label)}</span>'


def _human_label(value: str) -> str:
    return str(value).replace("_", " ").replace("-", " ").title()


def _metric(label: str, value: object, class_name: str = "") -> str:
    return (
        f'<div class="metric {h(class_name)}">'
        f'<span class="metric-value">{h(value)}</span>'
        f'<span class="metric-label">{h(label)}</span>'
        "</div>"
    )


def _list_html(items: list[Any], empty_text: str) -> str:
    if not items:
        return f"<li>{h(empty_text)}</li>"
    return "".join(f"<li>{h(item)}</li>" for item in items)


def _safe_json_for_script(value: object) -> str:
    return (
        json.dumps(value, sort_keys=True)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def _more_items_message(hidden_count: int, item_label: str) -> str:
    suffix = "" if hidden_count == 1 else "s"
    return f"{hidden_count} more {item_label}{suffix} not shown."


def _graph_index(graph: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    nodes = {node.get("id", ""): node for node in graph.get("nodes", [])}
    edges = {edge.get("id", ""): edge for edge in graph.get("edges", [])}
    return nodes, edges


def _node_class(node: dict[str, Any]) -> str:
    classes = ["graph-node", f"node-{node.get('type', 'unknown')}"]
    if node.get("type") == "unknown" or node.get("visibility_gaps"):
        classes.append("unknown")
    if node.get("type") == "approval_policy":
        classes.append("approval-node")
    if node.get("confidence") == "low":
        classes.append("low-confidence")
    return " ".join(classes)


def _edge_class(edge: dict[str, Any]) -> str:
    classes = ["graph-edge"]
    edge_type = edge.get("type", "")
    if edge_type in {"event_observed", "event_allowed"}:
        classes.append("observed-edge")
    if edge_type in {"event_blocked", "approval_present", "action_requires_approval"}:
        classes.append("blocked-edge")
    if edge.get("confidence") == "low":
        classes.append("low-confidence")
    return " ".join(classes)


def _node_html(node_ref: str, node: dict[str, Any]) -> str:
    layer = node.get("evidence_layer", "unknown")
    confidence = node.get("confidence", "unknown")
    return (
        f'<div class="{h(_node_class(node))}" title="layer={h(layer)} confidence={h(confidence)}">'
        f'<span>{h(node.get("label") or node_ref)}</span>'
        f'<small>{h(node.get("type", "unknown"))}</small>'
        "</div>"
    )


def _edge_html(edge: dict[str, Any], label: str = "then") -> str:
    edge_label = edge.get("label") or edge.get("type") or label
    return (
        f'<div class="{h(_edge_class(edge))}" title="layer={h(edge.get("evidence_layer", "unknown"))} '
        f'confidence={h(edge.get("confidence", "unknown"))}" aria-label="{h(edge_label)}">'
        f'<span>-&gt;</span><small>{h(edge_label)}</small></div>'
    )


def _path_graph_from_finding(finding: dict[str, Any], graph: dict[str, Any]) -> str:
    path_nodes = finding.get("nodes", [])
    path_edges = finding.get("edges", [])
    if not path_nodes:
        return '<div class="empty">No path nodes</div>'
    nodes_by_id, edges_by_id = _graph_index(graph)
    used_edges: set[str] = set()
    nodes = []
    for index, node_ref in enumerate(path_nodes):
        node = nodes_by_id.get(node_ref, {"id": node_ref, "type": "unknown", "label": node_ref, "confidence": "low"})
        nodes.append(_node_html(node_ref, node))
        if index < len(path_nodes) - 1:
            next_ref = path_nodes[index + 1]
            matching_edge_id = next(
                (
                    edge_id
                    for edge_id in path_edges
                    if edges_by_id.get(edge_id, {}).get("from_node") == node_ref
                    and edges_by_id.get(edge_id, {}).get("to_node") == next_ref
                ),
                "",
            )
            edge = edges_by_id.get(matching_edge_id, {})
            if matching_edge_id:
                used_edges.add(matching_edge_id)
            nodes.append(_edge_html(edge))
    support_edges = []
    for edge_ref in path_edges:
        if edge_ref in used_edges:
            continue
        edge = edges_by_id.get(edge_ref)
        if not edge:
            continue
        from_node = nodes_by_id.get(edge.get("from_node", ""), {"label": edge.get("from_node", ""), "type": "unknown"})
        to_node = nodes_by_id.get(edge.get("to_node", ""), {"label": edge.get("to_node", ""), "type": "unknown"})
        support_edges.append(
            '<div class="support-edge">'
            f'<span>{h(from_node.get("label") or edge.get("from_node", ""))}</span>'
            f'{_edge_html(edge)}'
            f'<span>{h(to_node.get("label") or edge.get("to_node", ""))}</span>'
            "</div>"
        )
    supporting = ""
    if support_edges:
        supporting = '<div class="supporting-edges"><h3>Supporting graph edges</h3>' + "".join(support_edges) + "</div>"
    return '<div class="path-graph">' + "".join(nodes) + "</div>" + supporting


def _control_status(finding: dict[str, Any]) -> str:
    if finding.get("runtime_observation", {}).get("state") == "observed_blocked":
        return "blocked"
    if any("gap-approval" in gap_id for gap_id in finding.get("visibility_gaps", [])):
        return "approval_missing"
    if finding.get("blockers") or finding.get("controls"):
        return "approval_present"
    return "unknown"


def _finding_card(finding: dict[str, Any], selected: bool = False) -> str:
    scoring = finding.get("scoring") or {}
    dimensions = scoring.get("dimensions", [])
    context = finding.get("operational_context", {}) or {}
    remediation = finding.get("remediation", {}) or {}
    accepted_risk = finding.get("accepted_risk", {}) or {}
    risk_status = str(finding.get("risk_status", "open"))
    path_preview = " -> ".join(str(item) for item in finding.get("path", [])[:6])
    next_action_items = (
        remediation.get("validation_steps", [])
        or remediation.get("recommended_controls", [])
        or finding.get("recommended_next_evidence", [])
        or finding.get("recommendations", [])
    )
    next_action = next_action_items[0] if next_action_items else "Review evidence details."
    searchable = " ".join(
        [
            str(finding.get("title", "")),
            str(finding.get("description", "")),
            str(finding.get("observation_status", "possible_static")),
            str(finding.get("path_state", "possible")),
            str(finding.get("evidence_quality", "incomplete")),
            risk_status,
            " ".join(str(value) for value in accepted_risk.values()),
            " ".join(str(value) for value in context.values()),
            " ".join(str(item) for item in finding.get("visibility_gap_priorities", [])),
            " ".join(str(item) for item in finding.get("path", [])),
            " ".join(str(item) for item in finding.get("evidence", [])),
            " ".join(str(item) for item in finding.get("visibility_gaps", [])),
            " ".join(str(item) for item in finding.get("recommended_next_evidence", [])),
            " ".join(str(item) for item in remediation.get("recommended_controls", [])),
            " ".join(str(item.get("name", "")) for item in dimensions),
            " ".join(str(item.get("evidence", "")) for item in dimensions),
        ]
    ).lower()
    searchable = " ".join([searchable, " ".join(privacy_filter_tokens_for_text(searchable))])
    badges = [
        _badge(str(finding.get("tier", "informational")).upper(), f"tier-{finding.get('tier', 'informational')}"),
        _badge(f"quality {finding.get('evidence_quality', 'incomplete')}"),
        _badge(_human_label(finding.get("path_state", "possible"))),
    ]
    if finding.get("related_events"):
        badges.append(_badge(str(finding.get("observation_status", "observed")).replace("_", " "), "observed"))
    if risk_status != "open":
        badges.append(_badge(_human_label(risk_status), "observed" if risk_status == "accepted" else "tier-high"))
    classes = "card selected" if selected else "card"
    return (
        f'<article class="{classes}" role="button" tabindex="0" data-finding-id="{h(finding.get("id", ""))}" '
        f'data-tier="{h(finding.get("tier", ""))}" '
        f'data-confidence="{h(finding.get("confidence", ""))}" '
        f'data-observed="{h(finding.get("observation_status", "possible_static"))}" '
        f'data-quality="{h(finding.get("evidence_quality", "incomplete"))}" '
        f'data-state="{h(finding.get("path_state", "possible"))}" '
        f'data-risk-status="{h(risk_status)}" '
        f'data-owner="{h(str(context.get("owner", "")).lower())}" '
        f'data-environment="{h(str(context.get("environment", "")).lower())}" '
        f'data-control="{h(_control_status(finding))}" '
        f'data-gap="{h(" ".join(finding.get("visibility_gap_priorities", [])))}" '
        f'data-search="{h(searchable)}">'
        '<div class="card-head">'
        f'<h2>{h(finding.get("title", ""))}</h2>'
        f'<span class="score">{h(finding.get("score", 0))}</span>'
        '</div>'
        f'<div class="badges">{"".join(badges)}</div>'
        '<div class="card-meta">'
        f'<span>Owner {h(context.get("owner") or "unknown")}</span>'
        f'<span>{h(context.get("environment") or "unknown")}</span>'
        f'<span>{h(context.get("approval_policy") or "unknown")}</span>'
        '</div>'
        f'<p class="path-preview">{h(path_preview)}</p>'
        f'<p class="next-action"><strong>Next:</strong> {h(next_action)}</p>'
        "</article>"
    )


def render_html(report: dict[str, Any], *, simple: bool = False) -> str:
    summary = report.get("summary", {})
    graph = report.get("graph", {})
    findings = sorted(report.get("findings", []), key=lambda item: (-int(item.get("score", 0)), item.get("id", "")))
    selected = findings[0] if findings else {}
    raw_json = json.dumps(selected or report, indent=2, sort_keys=True)
    if len(raw_json) > 24000:
        raw_json = raw_json[:24000] + "\n... truncated ..."

    finding_cards = "".join(_finding_card(finding, selected=(finding == selected)) for finding in findings)
    if not finding_cards:
        finding_cards = '<div class="empty">No findings produced.</div>'

    selected_badges = "".join(
        [
            _badge(str(selected.get("tier", "informational")).upper(), f"tier-{selected.get('tier', 'informational')}"),
            _badge(f"Score {selected.get('score', 0)}"),
            _badge(f"Raw points {selected.get('raw_points', selected.get('score', 0))}"),
            _badge(f"Confidence {selected.get('confidence', 'unknown')}"),
            _badge(f"Quality {_human_label(selected.get('evidence_quality', 'incomplete'))}"),
            _badge(_human_label(selected.get("path_state", "possible"))),
            _badge(f"Risk {_human_label(selected.get('risk_status', 'open'))}"),
            _badge(f"Runtime {_human_label((selected.get('runtime_observation') or {}).get('state', 'not_observed'))}"),
        ]
    )
    path_items = _list_html(selected.get("path", []), "No path recorded.")
    evidence = _list_html(selected.get("evidence", []), "No evidence recorded.")
    unknowns = _list_html(selected.get("unknowns", []), "No unknowns recorded.")
    blockers = _list_html(selected.get("blockers", []) + selected.get("controls", []), "No blockers or controls recorded.")
    visibility_gaps = _list_html(selected.get("visibility_gaps", []), "No visibility gaps attached to this finding.")
    next_evidence = _list_html(selected.get("recommended_next_evidence", []), "No next evidence request recorded.")
    recommendations = _list_html(selected.get("recommendations", []), "No recommendations recorded.")
    runtime_details = _list_html(
        [
            f"State: {(selected.get('runtime_observation') or {}).get('state', 'not_observed')}",
            f"Events: {', '.join((selected.get('runtime_observation') or {}).get('observed_events', [])) or 'none'}",
            f"Sessions: {', '.join((selected.get('runtime_observation') or {}).get('session_ids', [])) or 'none'}",
            f"Last observed: {(selected.get('runtime_observation') or {}).get('last_observed_at') or 'not observed'}",
            f"Sequence confidence: {(selected.get('runtime_observation') or {}).get('sequence_confidence', 'low')}",
            f"Explanation: {(selected.get('runtime_observation') or {}).get('explanation', '')}",
        ],
        "No runtime observation recorded.",
    )
    operational_context = _list_html(
        [
            f"Owner: {(selected.get('operational_context') or {}).get('owner') or 'unknown'}",
            f"Environment: {(selected.get('operational_context') or {}).get('environment') or 'unknown'}",
            f"Runtime: {(selected.get('operational_context') or {}).get('runtime') or 'unknown'}",
            f"Business unit: {(selected.get('operational_context') or {}).get('business_unit') or 'unknown'}",
            f"Policy: {(selected.get('operational_context') or {}).get('approval_policy') or 'unknown'}",
            f"Last observed: {(selected.get('operational_context') or {}).get('last_observed_at') or 'not observed'}",
        ],
        "No operational context recorded.",
    )
    accepted_risk = selected.get("accepted_risk") or {}
    accepted_risk_details = _list_html(
        [
            f"Status: {selected.get('risk_status', 'open')}",
            f"Accepted: {'yes' if accepted_risk.get('accepted') else 'no'}",
            f"Expired: {'yes' if accepted_risk.get('expired') else 'no'}",
            f"Owner: {accepted_risk.get('owner') or 'unknown'}",
            f"Expires: {accepted_risk.get('expires_at') or 'unspecified'}",
            f"Ticket: {accepted_risk.get('ticket') or 'none'}",
            f"Reason: {accepted_risk.get('reason') or 'not recorded'}",
        ],
        "No accepted risk metadata recorded.",
    )
    remediation = selected.get("remediation") or {}
    recommended_controls = _list_html(remediation.get("recommended_controls", []), "No recommended controls recorded.")
    validation_steps = _list_html(remediation.get("validation_steps", []), "No validation steps recorded.")
    required_next_evidence = _list_html(remediation.get("required_next_evidence", []), "No required next evidence recorded.")
    policy_snippet = h(json.dumps(remediation.get("policy_snippet"), indent=2, sort_keys=True)) if remediation.get("policy_snippet") else "No suggested policy rule recorded."
    source_files_list = _list_html(selected.get("source_files", []), "No source files recorded.")
    dimensions = "".join(
        f'<li><strong>{h(_human_label(item.get("name", "")))}</strong>: {h(item.get("points"))} <span>{h(item.get("evidence"))}</span></li>'
        for item in (selected.get("scoring") or {}).get("dimensions", [])
    )
    caps = _list_html((selected.get("scoring") or {}).get("caps", []), "No caps applied.")
    findings_json = _safe_json_for_script(findings)
    graph_json = _safe_json_for_script(graph)
    review_decision = report.get("review_decision", {})
    review_brief = report.get("review_brief", {})
    primary_risk = review_brief.get("primary_risk") or {}
    top_gap = (review_brief.get("top_visibility_gaps") or [{}])[0] if review_brief.get("top_visibility_gaps") else {}
    top_action = (review_brief.get("top_actions") or ["No top action recorded."])[0]
    primary_text = (
        f"{primary_risk.get('tier', 'unknown')} / score {primary_risk.get('score', 'unknown')} / "
        f"{primary_risk.get('evidence_quality', 'unknown')} / {primary_risk.get('path_state', 'unknown')}"
        if primary_risk
        else "No primary risk selected."
    )
    top_gap_text = (
        f"{top_gap.get('priority', 'medium_gap')}: {top_gap.get('type', 'unknown')} on {top_gap.get('target', 'unknown')}"
        if top_gap
        else "No priority visibility gaps recorded."
    )
    review_actions = _list_html(review_decision.get("required_actions", []), "No required actions recorded.")
    review_reasons = _list_html(review_decision.get("reasons", []), "No decision evidence recorded.")
    body_class = ' class="simple-mode"' if simple else ""
    mode_badge = '<span class="mode-badge">Simple mode</span>' if simple else ""
    brief_items = "".join(
        [
            '<div class="topline-item">'
            '<span class="brief-label">Evidence posture</span>'
            f'<strong>{h(review_brief.get("posture", "unknown"))}</strong>'
            "</div>",
            '<div class="topline-item">'
            '<span class="brief-label">Runtime posture</span>'
            f'<strong>{h(review_brief.get("runtime_posture", "unknown"))}</strong>'
            "</div>",
            '<div class="topline-item">'
            '<span class="brief-label">Primary risk</span>'
            f'<strong>{h(primary_risk.get("title", "No primary risk selected."))}</strong>'
            f'<small>{h(primary_text)}</small>'
            "</div>",
            '<div class="topline-item">'
            '<span class="brief-label">Top visibility gap</span>'
            f'<strong>{h(top_gap_text)}</strong>'
            f'<small>{h(top_gap.get("reason", ""))}</small>'
            "</div>",
            '<div class="topline-item brief-action">'
            '<span class="brief-label">Next action</span>'
            f'<strong>{h(top_action)}</strong>'
            "</div>",
        ]
    )
    remediation_plan = report.get("remediation_plan") or {}
    remediation_summary = remediation_plan.get("summary") or {}
    remediation_owner_rollup = _list_html(
        [
            f"{item.get('owner', 'unassigned')}: {item.get('action_count', 0)} actions "
            f"({item.get('p1', 0)} P1)"
            for item in remediation_plan.get("owner_rollups", [])[:8]
        ],
        "No owner remediation rollup recorded.",
    )
    remediation_category_rollup = _list_html(
        [
            f"{item.get('category', 'evidence')}: {item.get('action_count', 0)} actions "
            f"({item.get('p1', 0)} P1)"
            for item in remediation_plan.get("category_rollups", [])[:8]
        ],
        "No category remediation rollup recorded.",
    )
    remediation_actions = _list_html(
        [
            f"{item.get('priority', 'P2')}: {item.get('owner', 'unassigned')} -> {item.get('target', 'unknown')} "
            f"[{item.get('category', 'evidence')}] {item.get('reason', '')} "
            f"Next: {item.get('suggested_next_command') or item.get('requested_evidence') or 'Review related evidence.'} "
            f"Related: {', '.join((item.get('related_finding_ids') or []) + (item.get('related_gap_ids') or [])) or 'none'}"
            for item in remediation_plan.get("actions", [])[:12]
        ],
        "No remediation actions generated.",
    )
    evidence_guide = report.get("evidence_guide") or {}
    guide_sources = "".join(
        '<div class="guide-source">'
        f'<span class="brief-label">{h(source.get("label", source.get("kind", "unknown")))}</span>'
        f'<strong>{h(_human_label(source.get("status", "unknown")))} ({h(source.get("count", 0))})</strong>'
        f'<small>{h(source.get("notes", ""))}</small>'
        "</div>"
        for source in evidence_guide.get("evidence_sources", [])
    )
    if not guide_sources:
        guide_sources = '<div class="guide-source"><strong>No evidence source summary recorded.</strong></div>'
    guide_missing = _list_html(
        [
            f"{item.get('priority', 'medium_gap')}: {item.get('type', 'unknown')} on "
            f"{item.get('target', 'unknown')} - request {item.get('requested_evidence', '')}"
            for item in evidence_guide.get("top_missing_evidence", [])
        ],
        "No priority visibility gaps recorded.",
    )
    guide_commands = _list_html(evidence_guide.get("collection_commands", []), "No collection commands recorded.")
    guide_questions = _list_html(
        evidence_guide.get("security_team_questions", []),
        "No security team questions recorded.",
    )
    guide_inputs = _list_html(
        [
            f"{item.get('file', 'unknown')}: {item.get('why', '')}"
            for item in evidence_guide.get("recommended_next_inputs", [])
        ],
        "No recommended next inputs recorded.",
    )
    simple_risks = _list_html(
        [
            f"{finding.get('tier', 'informational')}: {finding.get('title', 'unknown')} "
            f"(score {(finding.get('scoring') or {}).get('score', finding.get('score', 'unknown'))}, "
            f"owner {(finding.get('operational_context') or {}).get('owner', 'unknown')})"
            for finding in findings[:5]
        ],
        "No attack-path findings produced.",
    )
    evidence_manifest = report.get("evidence_manifest") or {}
    manifest_summary = evidence_manifest.get("summary") or {}
    manifest_details = []
    for item in evidence_manifest.get("changed", [])[:8]:
        manifest_details.append(
            f"changed: {item.get('path', 'unknown')} ({', '.join(item.get('fields', [])) or 'metadata differs'})"
        )
    for item in evidence_manifest.get("missing", [])[:8]:
        reason = f" - {item.get('reason')}" if item.get("reason") else ""
        manifest_details.append(f"missing: {item.get('path', 'unknown')}{reason}")
    for item in evidence_manifest.get("unmanifested", [])[:8]:
        manifest_details.append(f"unmanifested: {item.get('path', 'unknown')}")
    for error in evidence_manifest.get("errors", [])[:8]:
        manifest_details.append(f"error: {error}")
    manifest_detail_list = _list_html(manifest_details, "No manifest differences recorded.")
    policy_analysis = report.get("policy_analysis") or {}
    policy_summary = policy_analysis.get("summary") or {}
    policy_evaluations = _list_html(
        [
            f"{item.get('engine', 'unknown')}: {item.get('decision', 'unknown')} "
            f"match={', '.join(item.get('match_keys', [])) or 'none'} "
            f"source={item.get('source_file', 'unknown')}"
            for item in policy_analysis.get("evaluations", [])[:16]
        ],
        "No policy evaluations recorded.",
    )
    policy_gaps = _list_html(
        [
            f"{item.get('type', 'unknown')}: {item.get('target', 'unknown')} - {item.get('repair', '')}"
            for item in policy_analysis.get("gaps", [])[:16]
        ],
        "No policy evaluation gaps recorded.",
    )
    policy_rule_risks = _list_html(
        [
            f"{item.get('type', 'unknown')}: {item.get('agent', 'unknown')} -> {item.get('tool', 'unknown')} "
            f"effective={item.get('effective_rule', 'unknown')} "
            f"policy={item.get('policy', 'unknown')} rule={item.get('rule', item.get('effective_rule', 'unknown'))} "
            f"decision={item.get('effective_decision', 'unknown')} - {item.get('reason', '')} "
            f"Repair: {item.get('repair', '')}"
            for item in policy_analysis.get("rule_risks", [])[:16]
        ],
        "No policy rule risks recorded.",
    )
    offline_control_analysis = report.get("offline_control_analysis") or {}
    offline_summary = offline_control_analysis.get("summary") or {}
    roadmap_items = offline_control_analysis.get("roadmap", [])
    roadmap_limit = 16
    roadmap_rows = [
        f"{item.get('priority', 'P2')}: {item.get('title', 'unknown')} "
        f"({item.get('affected_count', 0)} affected) - {item.get('reason', '')} "
        f"Evidence: {'; '.join(item.get('evidence_needed', [])[:2])} "
        f"Acceptance: {'; '.join(item.get('acceptance_criteria', [])[:2]) or 'not recorded'}"
        for item in roadmap_items[:roadmap_limit]
    ]
    hidden_roadmap_items = max(0, len(roadmap_items) - roadmap_limit)
    if hidden_roadmap_items:
        roadmap_rows.append(_more_items_message(hidden_roadmap_items, "offline remediation roadmap item"))
    offline_roadmap = _list_html(
        roadmap_rows,
        "No offline remediation roadmap items recorded.",
    )
    offline_generic_tools = _list_html(
        [
            f"{item.get('tool', 'unknown')}: {', '.join(item.get('broad_reasons', [])) or 'broad tool surface'}"
            for item in offline_control_analysis.get("generic_tools", [])[:16]
        ],
        "No generic tool surfaces detected.",
    )
    offline_control_gaps = _list_html(
        [
            f"{item.get('agent', 'unknown')} -> {item.get('tool', 'unknown')}: "
            f"{', '.join(item.get('missing_controls', []))}. {item.get('requested_evidence', '')}"
            for item in offline_control_analysis.get("policy_control_gaps", [])[:16]
        ],
        "No missing offline control evidence recorded.",
    )
    offline_prompt_boundaries = _list_html(
        [
            f"{item.get('agent', 'unknown')}: fields={', '.join(item.get('fields', []))} "
            f"terms={', '.join(item.get('matched_terms', []))}"
            for item in offline_control_analysis.get("prompt_security_boundaries", [])[:16]
        ],
        "No prompt-language security boundary evidence detected.",
    )
    privacy_analysis = report.get("privacy_analysis") or {}
    privacy_summary = privacy_analysis.get("summary") or {}
    privacy_exposures = _list_html(
        [
            f"{item.get('tier', 'unknown')}: {item.get('title', 'unknown')} "
            f"classes={', '.join(item.get('data_classes', [])) or 'unknown'} "
            f"categories={', '.join(item.get('privacy_categories', [])) or 'unmapped'}"
            for item in privacy_analysis.get("data_exposures", [])[:16]
        ],
        "No privacy-relevant data exposures recorded.",
    )
    privacy_classification_gaps = _list_html(
        [
            f"{item.get('type', 'unknown')}: {item.get('target', 'unknown')} - {item.get('requested_evidence', '')}"
            for item in privacy_analysis.get("classification_gaps", [])[:16]
        ],
        "No classification gaps recorded.",
    )
    privacy_memory_retention = _list_html(
        [
            f"{item.get('status', 'unknown')}: {item.get('id', 'unknown')} owner={item.get('owner') or 'unknown'} "
            f"retention={item.get('retention_policy', 'unknown')} period={item.get('retention_period') or 'unknown'} "
            f"deletion={item.get('deletion_policy') or 'unknown'}"
            for item in privacy_analysis.get("memory_retention", [])[:16]
        ],
        "No memory retention evidence recorded.",
    )
    runtime_reconstruction = report.get("runtime_reconstruction") or {}
    runtime_summary = runtime_reconstruction.get("summary") or {}
    runtime_quality = runtime_reconstruction.get("event_quality") or {}
    runtime_paths = _list_html(
        [
            f"{item.get('state', 'unknown')}: {item.get('agent', 'unknown')} session "
            f"{item.get('session_id', 'unknown')} tools={' -> '.join(item.get('tools', []))}"
            for item in runtime_reconstruction.get("event_derived_paths", [])
        ],
        "No event-derived paths reconstructed.",
    )
    runtime_diagnostics = _list_html(
        [
            f"{item.get('type', 'unknown')}: {item.get('event_id') or item.get('event_key', 'unknown')} - "
            f"{item.get('repair', '')}"
            for item in runtime_reconstruction.get("diagnostics", [])[:12]
        ],
        "No runtime correlation diagnostics.",
    )
    iam_analysis = report.get("iam_analysis") or {}
    iam_summary = iam_analysis.get("summary") or {}
    iam_bindings = _list_html(
        [
            f"{item.get('binding_type', 'unknown')}: {item.get('agent', 'unknown')} -> "
            f"{item.get('tool', 'unknown')} target={item.get('target_system', 'unknown')} "
            f"identities={', '.join(item.get('selected_identities') or item.get('candidate_identities') or []) or 'none'} "
            f"permissions={item.get('permission_status', 'unknown')}"
            for item in iam_analysis.get("binding_coverage", [])[:24]
        ],
        "No agent-tool binding coverage recorded.",
    )
    iam_unused_identities = _list_html(
        [
            f"{item.get('identity', 'unknown')} target={item.get('target_system', 'unknown')}: {item.get('reason', '')}"
            for item in iam_analysis.get("unused_identities", [])[:16]
        ],
        "No unused identities recorded.",
    )
    iam_unused_permissions = _list_html(
        [
            f"{item.get('identity', 'unknown')} {item.get('resource', 'unknown')} "
            f"{', '.join(item.get('actions', []))}: {item.get('reason', '')}"
            for item in iam_analysis.get("unused_permissions", [])[:16]
        ],
        "No unused permissions recorded.",
    )
    iam_suggestions = _list_html(
        [
            f"{item.get('priority', 'P2')}: {item.get('target_system', 'unknown')} "
            f"{item.get('identity') or item.get('tool') or ''}: {item.get('suggestion', '')}"
            for item in iam_analysis.get("least_privilege_suggestions", [])[:16]
        ],
        "No least-privilege suggestions recorded.",
    )

    metrics = "".join(
        [
            _metric("Findings", len(findings)),
            _metric("Urgent", summary.get("urgent", 0), "metric-urgent"),
            _metric("High", summary.get("high", 0), "metric-high"),
            _metric("Supported", summary.get("supported", 0)),
            _metric("Visibility Gaps", summary.get("visibility_gaps", 0)),
            _metric("Accepted Risk", summary.get("accepted_risk_findings", 0)),
            _metric("Ambiguous Bindings", summary.get("ambiguous_bindings", 0)),
            _metric("Generic Tools", summary.get("generic_tools", 0)),
            _metric("Missing Controls", summary.get("tools_missing_required_controls", 0)),
            _metric("Remediation P1", remediation_summary.get("p1", 0), "metric-high"),
            _metric("Observed Blocked", summary.get("observed_blocked", 0)),
            _metric("Policy Evals", summary.get("policy_evaluations", 0)),
        ]
    )
    agents = sorted(str(agent.get("id", "")) for agent in report.get("inventory", {}).get("agents", []) if agent.get("id"))
    agent_options = "".join(f'<option value="{h(agent.lower())}">{h(agent)}</option>' for agent in agents)
    owners = sorted({str((finding.get("operational_context") or {}).get("owner", "")) for finding in findings if (finding.get("operational_context") or {}).get("owner")})
    environments = sorted({str((finding.get("operational_context") or {}).get("environment", "")) for finding in findings if (finding.get("operational_context") or {}).get("environment")})
    owner_options = "".join(f'<option value="{h(owner.lower())}">{h(owner)}</option>' for owner in owners)
    environment_options = "".join(f'<option value="{h(environment.lower())}">{h(environment)}</option>' for environment in environments)
    simple_overview = ""
    if simple:
        simple_overview = f"""
<section class="simple-overview" aria-label="simple report overview">
  <div class="simple-card simple-card-primary">
    <span class="brief-label">What matters</span>
    <h2>{h(review_decision.get("label", review_decision.get("decision", "Unknown")))}</h2>
    <p>{h(review_decision.get("reason", "No decision reason recorded."))}</p>
    <ul>
      <li>{h(summary.get("urgent", 0))} urgent and {h(summary.get("high", 0))} high findings.</li>
      <li>{h(summary.get("visibility_gaps", 0))} visibility gaps need evidence.</li>
      <li>{h(summary.get("tools_missing_required_controls", 0))} tool/control gaps need review.</li>
    </ul>
  </div>
  <div class="simple-card">
    <span class="brief-label">Fix first</span>
    <ul>{review_actions}</ul>
  </div>
  <div class="simple-card">
    <span class="brief-label">Evidence to request</span>
    <ul>{guide_missing}</ul>
  </div>
  <div class="simple-card">
    <span class="brief-label">Top risks</span>
    <ul>{simple_risks}</ul>
  </div>
</section>
<p class="simple-note">Simple mode keeps the full JSON report but hides advanced scoring and raw-evidence detail in the HTML view. Re-run without <code>--simple</code> for the full reviewer interface.</p>
"""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentGuard Graph Report</title>
<style>
:root {{
  --bg: #f4f7fb;
  --panel: #ffffff;
  --panel-soft: #f8fafc;
  --panel-strong: #e8eef7;
  --nav: #152033;
  --nav-2: #24324a;
  --text: #172033;
  --muted: #667085;
  --muted-strong: #344054;
  --line: #d8e0ea;
  --line-strong: #aebbd0;
  --accent: #147e7e;
  --accent-2: #3156a3;
  --accent-3: #7c3aed;
  --accent-soft: #e7f6f5;
  --urgent: #c0263f;
  --high: #d35b1f;
  --medium: #b7791f;
  --low: #3156a3;
  --info: #475467;
  --ok: #13795b;
  --warn-soft: #fff4e6;
  --danger-soft: #fff0f3;
  --ok-soft: #e9f8f2;
  --blue-soft: #edf4ff;
  --purple-soft: #f4f0ff;
  --shadow-soft: 0 1px 2px rgba(23, 32, 51, 0.08);
  --shadow-panel: 0 10px 24px rgba(23, 32, 51, 0.08);
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, Helvetica, sans-serif;
  color: var(--text);
  background: var(--bg);
  font-size: 13px;
}}
header {{
  padding: 14px 18px 0;
  border-bottom: 1px solid #23324c;
  border-top: 4px solid var(--accent);
  background: var(--nav);
  color: #ffffff;
}}
.header-top {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
}}
.eyebrow {{
  margin: 0 0 4px;
  color: inherit;
  opacity: 0.74;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0;
  text-transform: uppercase;
}}
h1 {{ margin: 0; font-size: 21px; line-height: 1.15; font-weight: 760; }}
h2 {{ margin: 0 0 8px; font-size: 15px; line-height: 1.25; font-weight: 740; }}
h3 {{ margin: 14px 0 7px; font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0; }}
p {{ line-height: 1.45; }}
.subtitle {{
  max-width: 820px;
  margin: 4px 0 0;
  color: #b8c5d8;
}}
.metrics {{
  display: grid;
  grid-template-columns: repeat(6, minmax(92px, 1fr));
  gap: 1px;
  margin-top: 14px;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-bottom: 0;
  border-radius: 8px 8px 0 0;
  overflow: hidden;
  background: rgba(255, 255, 255, 0.12);
}}
.decision-chip {{
  min-width: 260px;
  max-width: 420px;
  padding: 8px 10px;
  border: 1px solid rgba(255, 255, 255, 0.16);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.08);
  box-shadow: inset 3px 0 0 var(--accent);
}}
.decision-chip h2 {{ margin: 0; font-size: 13px; color: #ffffff; }}
.decision-chip p {{
  display: none;
}}
.mode-badge {{
  display: inline-flex;
  align-items: center;
  min-height: 24px;
  padding: 3px 8px;
  border: 1px solid rgba(255, 255, 255, 0.18);
  border-radius: 999px;
  color: #d8fff8;
  background: rgba(20, 126, 126, 0.28);
  font-size: 11px;
  font-weight: 750;
}}
.simple-overview {{
  display: grid;
  grid-template-columns: 1.2fr 1fr 1fr 1fr;
  gap: 12px;
  padding: 14px 18px;
  background: #eaf1f8;
  border-bottom: 1px solid var(--line);
}}
.simple-card {{
  min-height: 132px;
  padding: 13px 14px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #ffffff;
  box-shadow: var(--shadow-soft);
}}
.simple-card-primary {{
  border-color: #9fd6d3;
  box-shadow: inset 4px 0 0 var(--accent), var(--shadow-soft);
}}
.simple-card h2 {{ margin: 5px 0 7px; font-size: 16px; }}
.simple-card p {{ margin: 0 0 8px; color: var(--muted-strong); }}
.simple-card ul {{ margin: 8px 0 0; padding-left: 18px; }}
.simple-card li {{ margin: 5px 0; line-height: 1.35; }}
.simple-note {{
  margin: 0;
  padding: 8px 18px;
  color: var(--muted-strong);
  background: #f8fafc;
  border-bottom: 1px solid var(--line);
}}
.simple-mode .advanced-only {{
  display: none;
}}
.simple-mode #remediation-plan.secondary-panel > summary::after,
.simple-mode #evidence-guide.secondary-panel > summary::after,
.simple-mode #policy-analysis.secondary-panel > summary::after,
.simple-mode #offline-control-analysis.secondary-panel > summary::after,
.simple-mode #privacy-analysis.secondary-panel > summary::after,
.simple-mode #iam-analysis.secondary-panel > summary::after,
.simple-mode #runtime-reconstruction.secondary-panel > summary::after {{
  content: "advanced";
  margin-left: 8px;
  padding: 2px 6px;
  border-radius: 999px;
  color: var(--muted);
  background: var(--panel-strong);
  font-size: 10px;
  text-transform: uppercase;
}}
.topline {{
  display: grid;
  grid-template-columns: 1fr 1fr 2fr 2fr 1.5fr;
  gap: 1px;
  border-top: 1px solid rgba(255, 255, 255, 0.12);
  background: rgba(255, 255, 255, 0.12);
}}
.topline-item {{
  display: grid;
  align-content: start;
  gap: 3px;
  min-height: 0;
  height: 52px;
  padding: 8px 11px;
  border-right: 0;
  background: var(--nav-2);
  overflow: hidden;
}}
.topline-item:last-child {{ border-right: 0; }}
.topline-item strong {{
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  line-height: 1.25;
  overflow: hidden;
  overflow-wrap: anywhere;
}}
.topline-item small {{
  display: none;
  color: var(--muted);
  line-height: 1.35;
  overflow-wrap: anywhere;
}}
.brief-label {{
  color: inherit;
  opacity: 0.64;
  font-size: 11px;
  font-weight: 750;
  letter-spacing: 0;
  text-transform: uppercase;
}}
.brief-action {{
  background: #163b4a;
}}
.guide-grid {{
  display: grid;
  grid-template-columns: repeat(6, minmax(130px, 1fr));
  gap: 1px;
  margin-bottom: 12px;
  border: 1px solid var(--line);
  border-radius: 8px;
  overflow: hidden;
  background: var(--line);
}}
.guide-source {{
  display: grid;
  gap: 4px;
  min-height: 86px;
  padding: 10px 11px;
  background: var(--panel-soft);
}}
.guide-source strong {{
  line-height: 1.25;
}}
.guide-source small {{
  color: var(--muted);
  line-height: 1.35;
}}
.guide-columns {{
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 18px;
}}
.metric {{
  position: relative;
  border-right: 0;
  border-radius: 0;
  padding: 9px 10px 8px 13px;
  background: #1d2a40;
  color: #ffffff;
}}
.metric:last-child {{ border-right: 0; }}
.metric::before {{
  content: "";
  position: absolute;
  left: 0;
  top: 0;
  width: 4px;
  height: 100%;
  background: var(--metric-accent, var(--accent));
}}
.metric:nth-child(1) {{ --metric-accent: var(--accent-2); }}
.metric:nth-child(4) {{ --metric-accent: var(--ok); }}
.metric:nth-child(5) {{ --metric-accent: var(--accent-3); }}
.metric:nth-child(6) {{ --metric-accent: var(--urgent); }}
.metric-value {{
  display: block;
  font-size: 17px;
  font-weight: 750;
  line-height: 1.05;
}}
.metric-label {{
  display: block;
  margin-top: 2px;
  color: #b8c5d8;
  font-size: 11px;
}}
.metric-urgent {{ --metric-accent: var(--urgent); background: #321d29; }}
.metric-high {{ --metric-accent: var(--high); background: #342719; }}
.badges {{ display: flex; flex-wrap: wrap; gap: 6px; }}
.badge {{
  display: inline-flex;
  align-items: center;
  min-height: 21px;
  padding: 2px 7px;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: #f7f9fc;
  font-size: 11px;
  color: var(--text);
}}
.tier-urgent {{ border-color: var(--urgent); color: var(--urgent); }}
.tier-high {{ border-color: var(--high); color: var(--high); }}
.tier-medium {{ border-color: var(--medium); color: var(--medium); }}
.observed {{ border-style: solid; color: var(--ok); }}
.possible {{ border-style: dashed; }}
.layout {{
  display: grid;
  grid-template-columns: minmax(360px, 440px) minmax(540px, 1fr) minmax(370px, 460px);
  align-items: start;
  min-height: calc(100vh - 155px);
  min-width: 0;
}}
.risk-view, .path-panel, .detail-panel {{
  min-width: 0;
  padding: 16px 18px;
  overflow: auto;
}}
.risk-view {{
  min-height: calc(100vh - 155px);
  max-height: calc(100vh - 155px);
  background: #edf2f8;
  border-right: 1px solid var(--line);
}}
.path-panel {{
  position: sticky;
  top: 0;
  min-height: calc(100vh - 155px);
  max-height: calc(100vh - 155px);
  background: var(--panel);
  border-right: 1px solid var(--line);
}}
.detail-panel {{
  min-height: calc(100vh - 155px);
  max-height: calc(100vh - 155px);
  background: #fbfcff;
}}
.pane-title {{
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}}
.pane-title p {{ margin: 0; }}
.filters {{
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 8px;
  margin: 10px 0 14px;
}}
.filter, select, input, button {{
  border: 1px solid var(--line);
  border-radius: 7px;
  padding: 8px 9px;
  font-size: 12px;
  background: var(--panel);
}}
.filter-search {{ grid-column: 1 / -1; }}
label.filter {{ display: grid; gap: 4px; color: var(--muted); }}
.quick-search {{
  display: block;
  margin-bottom: 7px;
  padding: 0;
  border: 0;
  background: transparent;
  font-size: 0;
}}
.quick-search input {{
  height: 36px;
  font-size: 12px;
  border-color: #c6d2e2;
  box-shadow: var(--shadow-soft);
}}
select, input {{ width: 100%; color: var(--text); }}
button {{
  color: var(--text);
  cursor: pointer;
  background: #f7f9fc;
}}
.filter-actions {{
  grid-column: 1 / -1;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}}
.filter-shell {{
  margin-bottom: 12px;
}}
.filter-shell summary {{
  cursor: pointer;
  color: var(--muted-strong);
  font-size: 12px;
  font-weight: 700;
  list-style-position: inside;
}}
.filter-shell[open] {{
  padding-bottom: 2px;
}}
.card {{
  display: block;
  width: 100%;
  color: inherit;
  text-align: left;
  border: 1px solid var(--line);
  border-left: 4px solid var(--line-strong);
  border-radius: 8px;
  padding: 11px 12px;
  margin-bottom: 8px;
  background: var(--panel);
  cursor: pointer;
  box-shadow: var(--shadow-soft);
  transition: border-color 120ms ease, box-shadow 120ms ease, background 120ms ease, transform 120ms ease;
}}
.card:hover, .card:focus {{ border-color: var(--accent); outline: none; box-shadow: var(--shadow-panel); transform: translateY(-1px); }}
.card[data-tier="urgent"] {{ border-left-color: var(--urgent); }}
.card[data-tier="high"] {{ border-left-color: var(--high); }}
.card[data-tier="medium"] {{ border-left-color: var(--medium); }}
.card[data-tier="low"] {{ border-left-color: var(--low); }}
.selected {{ outline: 2px solid rgba(20, 126, 126, 0.18); border-color: var(--accent); background: var(--accent-soft); }}
.card-head {{
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
}}
.card-head h2 {{
  margin-bottom: 6px;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}}
.score {{
  min-width: 38px;
  min-height: 28px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 6px;
  background: #172033;
  color: #ffffff;
  font-weight: 750;
  font-size: 14px;
}}
.card-meta {{
  display: flex;
  flex-wrap: wrap;
  gap: 6px 10px;
  margin-top: 8px;
  color: var(--muted);
  font-size: 11px;
}}
.path-preview {{
  margin: 9px 0 5px;
  color: var(--muted);
  font-size: 12px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  overflow-wrap: anywhere;
}}
.next-action {{
  margin: 7px 0;
  padding: 0;
  border-left: 0;
  border-radius: 0;
  background: transparent;
  color: var(--muted-strong);
  font-size: 12px;
  line-height: 1.35;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}}
.small {{ color: var(--muted); font-size: 12px; }}
.selected-summary {{
  border: 0;
  border-bottom: 1px solid var(--line);
  border-radius: 0;
  padding: 0 0 12px;
  background: var(--panel);
  margin-bottom: 12px;
}}
.selected-summary p {{ margin: 8px 0 0; color: var(--muted); }}
.graph-toolbar {{
  display: flex;
  flex-direction: row;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  margin: 0 0 12px;
}}
.legend {{
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  color: var(--muted);
  font-size: 12px;
}}
.legend span {{
  display: inline-flex;
  align-items: center;
  gap: 5px;
}}
.legend span::before {{
  content: "";
  width: 14px;
  height: 8px;
  border: 1px solid var(--line-strong);
  border-radius: 3px;
  background: var(--panel);
}}
.legend .legend-gap::before {{ border-style: dashed; }}
.legend .legend-control::before {{ border-color: var(--ok); background: var(--ok-soft); }}
.legend .legend-observed::before {{ border-color: var(--ok); }}
.path-graph {{
  display: flex;
  align-items: center;
  gap: 13px;
  flex-wrap: nowrap;
  min-height: 180px;
  max-width: 100%;
  overflow-x: auto;
  padding: 14px;
  background: #f5f8fc;
  border: 1px solid var(--line);
  border-radius: 8px;
}}
.graph-node {{
  min-width: 160px;
  max-width: 210px;
  min-height: 78px;
  display: inline-flex;
  flex-direction: column;
  gap: 6px;
  align-items: flex-start;
  justify-content: center;
  text-align: left;
  padding: 11px 13px;
  border: 1px solid #b8c7da;
  border-top: 3px solid var(--accent);
  border-radius: 8px;
  background: #ffffff;
  box-shadow: var(--shadow-soft);
  overflow-wrap: anywhere;
  flex: 0 0 auto;
}}
.graph-node small, .graph-edge small {{
  display: block;
  color: var(--muted);
  font-size: 10px;
  overflow-wrap: anywhere;
}}
.graph-node span {{
  font-weight: 750;
  color: var(--text);
}}
.graph-node small {{
  order: -1;
  color: var(--muted-strong);
  font-weight: 700;
  text-transform: uppercase;
}}
.node-input_source {{ border-top-color: var(--accent-3); }}
.node-agent {{ border-top-color: var(--accent-2); }}
.node-tool, .node-api_operation {{ border-top-color: var(--accent); }}
.node-data_source, .node-memory_store {{ border-top-color: var(--medium); }}
.node-external_sink {{ border-top-color: var(--urgent); }}
.node-identity, .node-permission {{ border-top-color: #475569; }}
.graph-node.unknown {{ border-style: dashed; }}
.graph-node.approval-node {{ border-color: var(--ok); background: var(--ok-soft); }}
.graph-node.approval-node::before {{ content: "approval"; font-size: 10px; color: var(--ok); }}
.graph-node.low-confidence {{ border-style: dashed; }}
.graph-edge {{
  color: var(--muted);
  font-weight: bold;
  display: grid;
  justify-items: center;
  align-content: center;
  min-width: 82px;
  flex: 0 0 82px;
}}
.graph-edge span {{
  position: relative;
  display: block;
  width: 72px;
  height: 2px;
  margin-bottom: 8px;
  overflow: hidden;
  color: transparent;
  background: var(--line-strong);
}}
.graph-edge span::after {{
  content: "";
  position: absolute;
  right: 0;
  top: -4px;
  width: 0;
  height: 0;
  border-left: 9px solid var(--line-strong);
  border-top: 5px solid transparent;
  border-bottom: 5px solid transparent;
}}
.graph-edge.observed-edge {{ color: var(--ok); }}
.graph-edge.observed-edge span {{ background: var(--ok); }}
.graph-edge.observed-edge span::after {{ border-left-color: var(--ok); }}
.graph-edge.blocked-edge {{ color: var(--urgent); }}
.graph-edge.blocked-edge span {{ background: var(--urgent); }}
.graph-edge.blocked-edge span::after {{ border-left-color: var(--urgent); }}
.graph-edge.low-confidence span {{ background: repeating-linear-gradient(90deg, var(--muted) 0 6px, transparent 6px 10px); }}
.supporting-edges {{
  margin-top: 12px;
  padding: 10px 12px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #f5f8fc;
}}
.supporting-edges h3 {{ margin-top: 0; }}
.support-edge {{
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-top: 8px;
  color: var(--muted);
  font-size: 12px;
}}
ol, ul {{ padding-left: 18px; }}
li {{ margin-bottom: 6px; }}
details {{
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 9px 11px;
  background: var(--panel);
  margin-bottom: 8px;
  box-shadow: var(--shadow-soft);
}}
.detail-group summary {{
  cursor: pointer;
  font-weight: 700;
  color: var(--text);
}}
.detail-group h3:first-of-type {{
  margin-top: 12px;
}}
pre {{
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 420px;
  overflow: auto;
  font-size: 12px;
}}
.empty {{
  color: var(--muted);
  border: 1px dashed var(--line);
  border-radius: 8px;
  padding: 18px;
}}
.hidden {{ display: none; }}
.secondary {{
  padding: 16px 18px 26px;
  border-top: 1px solid var(--line);
  background: #edf2f8;
}}
.secondary-panel {{
  max-width: 1600px;
  margin: 0 auto 10px;
  background: var(--panel);
}}
.secondary-panel > summary {{
  cursor: pointer;
  font-weight: 700;
}}
@media (max-width: 1180px) {{
  .metrics {{ grid-template-columns: repeat(3, minmax(90px, 1fr)); }}
  .topline {{ grid-template-columns: repeat(2, minmax(160px, 1fr)); }}
  .guide-grid {{ grid-template-columns: repeat(3, minmax(130px, 1fr)); }}
  .guide-columns {{ grid-template-columns: 1fr; }}
  .layout {{ grid-template-columns: 1fr; }}
  .risk-view, .path-panel, .detail-panel {{ min-height: auto; max-height: none; }}
  .risk-view {{ border-right: 0; border-bottom: 1px solid var(--line); }}
  .path-panel {{ position: static; border-right: 0; border-bottom: 1px solid var(--line); }}
}}
@media (max-width: 820px) {{
  .header-top {{ display: block; }}
  .decision-chip {{ min-width: 0; max-width: none; margin-top: 10px; }}
  .metrics {{ grid-template-columns: repeat(2, minmax(112px, 1fr)); }}
  .topline {{ grid-template-columns: 1fr; }}
  .simple-overview {{ grid-template-columns: 1fr; }}
  .guide-grid {{ grid-template-columns: 1fr; }}
  .layout {{ grid-template-columns: 1fr; }}
  .filters {{ grid-template-columns: 1fr; }}
  .filter-search, .filter-actions {{ grid-column: auto; }}
}}
</style>
</head>
<body{body_class}>
<header>
  <div class="header-top">
    <div>
      <p class="eyebrow">Security operations report</p>
      <h1>AgentGuard Graph Risk Report {mode_badge}</h1>
      <p class="subtitle">Agent risk, controls, and evidence gaps.</p>
    </div>
    <div class="decision-chip" aria-label="review decision">
      <p class="eyebrow">Review decision</p>
      <h2>{h(review_decision.get("label", review_decision.get("decision", "Unknown")))}</h2>
      <p>{h(review_decision.get("reason", ""))}</p>
    </div>
  </div>
  <section class="metrics" aria-label="report summary">{metrics}</section>
  <section class="topline" aria-label="Review brief">{brief_items}</section>
</header>
{simple_overview}
<div class="layout">
  <main class="risk-view">
    <div class="pane-title">
      <h2>Risk Queue</h2>
      <p class="small"><span id="match-count">{h(len(findings))}</span> shown, ranked by score</p>
    </div>
    <label class="filter filter-search quick-search">Search
      <input id="filter-search" type="search" placeholder="Search paths, tools, data classes, evidence">
    </label>
    <details class="filter-shell">
      <summary>Filters</summary>
    <div class="filters" aria-label="finding filters">
      <label class="filter">Tier
        <select id="filter-tier">
          <option value="">All</option>
          <option value="urgent">Urgent</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </select>
      </label>
      <label class="filter">Agent
        <select id="filter-agent">
          <option value="">All</option>
          {agent_options}
        </select>
      </label>
      <label class="filter">Evidence quality
        <select id="filter-quality">
          <option value="">All</option>
          <option value="confirmed">Confirmed</option>
          <option value="supported">Supported</option>
          <option value="incomplete">Incomplete</option>
          <option value="weak">Weak</option>
        </select>
      </label>
      <label class="filter">Path state
        <select id="filter-state">
          <option value="">All</option>
          <option value="possible">Possible</option>
          <option value="supported">Supported</option>
          <option value="observed_partial">Observed partial</option>
          <option value="observed_full">Observed full</option>
          <option value="observed_allowed">Observed allowed</option>
          <option value="observed_blocked">Observed blocked</option>
          <option value="unknown">Unknown</option>
        </select>
      </label>
      <label class="filter">Owner
        <select id="filter-owner">
          <option value="">All</option>
          {owner_options}
        </select>
      </label>
      <label class="filter">Environment
        <select id="filter-environment">
          <option value="">All</option>
          {environment_options}
        </select>
      </label>
      <label class="filter">Tool risk
        <select id="filter-risk">
          <option value="">All</option>
          <option value="command_execution">Command execution</option>
          <option value="external_sink">External sink</option>
          <option value="financial_action">Financial action</option>
          <option value="production_write">Production write</option>
          <option value="secret_access">Secret access</option>
        </select>
      </label>
      <label class="filter">Data class
        <select id="filter-data">
          <option value="">All</option>
          <option value="customer_pii">Customer PII</option>
          <option value="employee_data">Employee data</option>
          <option value="credentials">Credentials</option>
          <option value="payment_data">Payment data</option>
          <option value="source_code">Source code</option>
          <option value="regulated_records">Regulated records</option>
        </select>
      </label>
      <label class="filter">Confidence
        <select id="filter-confidence">
          <option value="">All</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </label>
      <label class="filter">Observed vs possible
        <select id="filter-observed">
          <option value="">All</option>
          <option value="possible_static">Possible/static</option>
          <option value="observed_allowed">Observed allowed</option>
          <option value="observed_blocked">Observed blocked</option>
        </select>
      </label>
      <label class="filter">Visibility gap priority
        <select id="filter-gap">
          <option value="">All</option>
          <option value="critical_gap">Critical gap</option>
          <option value="high_gap">High gap</option>
          <option value="medium_gap">Medium gap</option>
          <option value="low_gap">Low gap</option>
        </select>
      </label>
      <label class="filter">Control status
        <select id="filter-control">
          <option value="">All</option>
          <option value="approval_missing">Approval missing</option>
          <option value="approval_present">Approval present</option>
          <option value="blocked">Blocked</option>
          <option value="unknown">Unknown</option>
        </select>
      </label>
      <div class="filter-actions">
        <button id="clear-filters" type="button">Clear filters</button>
        <span class="small">Filters search evidence, path labels, scoring drivers, and gaps.</span>
      </div>
    </div>
    </details>
    <div id="finding-list" aria-label="ranked risk list">{finding_cards}</div>
    <div id="filtered-empty" class="empty hidden">No findings match the current filters.</div>
  </main>
  <aside class="path-panel" aria-label="selected attack path">
    <section class="selected-summary">
      <p class="eyebrow">Selected risk</p>
      <h2 id="selected-title">{h(selected.get("title", "No selected attack path"))}</h2>
      <div id="selected-badges" class="badges">{selected_badges}</div>
      <p id="selected-description">{h(selected.get("description", ""))}</p>
    </section>
    <div class="graph-toolbar">
      <h2>Attack Path Map</h2>
      <div class="legend" aria-label="graph legend">
        <span>Node</span>
        <span class="legend-gap">Gap</span>
        <span class="legend-control">Approval/control</span>
        <span class="legend-observed">Observed edge</span>
      </div>
    </div>
    <div id="path-graph-panel">{_path_graph_from_finding(selected, graph)}</div>
  </aside>
  <section class="detail-panel" aria-label="selected risk details">
    <h2>Evidence Details</h2>
    <details class="detail-group" open>
      <summary>Path and observation</summary>
    <h3>Path</h3>
    <ol id="path-list">{path_items}</ol>
    <h3>Evidence quality</h3>
    <ul id="quality-list"><li>Evidence quality: {h(selected.get('evidence_quality', 'incomplete'))}</li><li>Path state: {h(selected.get('path_state', 'possible'))}</li></ul>
    <h3>Accepted risk status</h3>
    <ul id="accepted-risk-list">{accepted_risk_details}</ul>
    <h3>Operational context</h3>
    <ul id="operational-context-list">{operational_context}</ul>
    <h3>Runtime observations</h3>
    <ul id="runtime-list">{runtime_details}</ul>
    </details>
    <details class="detail-group">
      <summary>Evidence and gaps</summary>
    <h3>Evidence used</h3>
    <ul id="evidence-list">{evidence or "<li>No evidence recorded.</li>"}</ul>
    <h3>Missing evidence / visibility gaps</h3>
    <ul id="visibility-gaps-list">{visibility_gaps}</ul>
    <h3>Unknowns</h3>
    <ul id="unknowns-list">{unknowns or "<li>No unknowns recorded.</li>"}</ul>
    <h3>Next Evidence To Request</h3>
    <ul id="next-evidence-list">{next_evidence}</ul>
    <h3>Controls / blockers</h3>
    <ul id="blockers-list">{blockers or "<li>No blockers or controls recorded.</li>"}</ul>
    </details>
    <details class="detail-group">
      <summary>Remediation</summary>
    <h3>Recommended fixes</h3>
    <ul id="recommendations-list">{recommendations or "<li>No recommendations recorded.</li>"}</ul>
    <h3>Recommended controls</h3>
    <ul id="recommended-controls-list">{recommended_controls}</ul>
    <h3>Suggested policy</h3>
    <pre id="policy-snippet">{policy_snippet}</pre>
    <h3>Required next evidence</h3>
    <ul id="required-next-evidence-list">{required_next_evidence}</ul>
    <h3>Validation steps</h3>
    <ul id="validation-steps-list">{validation_steps}</ul>
    </details>
    <details class="detail-group advanced-only">
      <summary>Scoring and raw evidence</summary>
    <h3>Scoring dimensions</h3>
    <ul id="dimensions-list">{dimensions or "<li>No scoring dimensions recorded.</li>"}</ul>
    <h3>Score caps</h3>
    <ul id="caps-list">{caps or "<li>No caps applied.</li>"}</ul>
    <h3>Source Files</h3>
    <ul id="source-files-list">{source_files_list}</ul>
    <details>
      <summary>Raw JSON</summary>
      <pre id="raw-json">{h(raw_json)}</pre>
    </details>
    </details>
  </section>
</div>
<section class="secondary" aria-label="supporting material">
  <details id="remediation-plan" class="secondary-panel"{'' if simple else ' open'}>
    <summary>Owner-Routed Remediation Plan</summary>
    <div class="topline">
      <div class="topline-item"><span class="brief-label">Actions</span><strong>{h(remediation_summary.get("actions", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">P1</span><strong>{h(remediation_summary.get("p1", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">P2</span><strong>{h(remediation_summary.get("p2", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">P3</span><strong>{h(remediation_summary.get("p3", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Owners</span><strong>{h(remediation_summary.get("owners", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Systems</span><strong>{h(remediation_summary.get("systems", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Categories</span><strong>{h(remediation_summary.get("categories", 0))}</strong></div>
    </div>
    <div class="guide-columns">
      <div>
        <h3>Owner rollup</h3>
        <ul>{remediation_owner_rollup}</ul>
      </div>
      <div>
        <h3>Category rollup</h3>
        <ul>{remediation_category_rollup}</ul>
      </div>
      <div>
        <h3>Priority actions</h3>
        <ul>{remediation_actions}</ul>
      </div>
    </div>
  </details>
  <details id="evidence-manifest" class="secondary-panel">
    <summary>Evidence Manifest Attestation</summary>
    <div class="topline">
      <div class="topline-item"><span class="brief-label">Status</span><strong>{h(_human_label(evidence_manifest.get("status", "not_provided")))}</strong></div>
      <div class="topline-item"><span class="brief-label">Checked files</span><strong>{h(manifest_summary.get("checked_count", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Changed files</span><strong>{h(manifest_summary.get("changed_count", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Missing files</span><strong>{h(manifest_summary.get("missing_count", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Unmanifested files</span><strong>{h(manifest_summary.get("unmanifested_count", 0))}</strong></div>
    </div>
    <p>Manifest path: {h(evidence_manifest.get("path") or "not provided")}</p>
    <h3>Manifest details</h3>
    <ul>{manifest_detail_list}</ul>
  </details>
  <details id="evidence-guide" class="secondary-panel">
    <summary>Evidence Collection Guide</summary>
    <p>{h(evidence_guide.get("summary", "No evidence collection guide recorded."))}</p>
    <div class="guide-grid" aria-label="Evidence source posture">{guide_sources}</div>
    <div class="guide-columns">
      <div>
        <h3>Top missing evidence</h3>
        <ul>{guide_missing}</ul>
      </div>
      <div>
        <h3>Collection commands</h3>
        <ul>{guide_commands}</ul>
        <h3>Recommended next inputs</h3>
        <ul>{guide_inputs}</ul>
      </div>
      <div>
        <h3>Security team questions</h3>
        <ul>{guide_questions}</ul>
      </div>
    </div>
  </details>
  <details id="policy-analysis" class="secondary-panel">
    <summary>Policy Evaluation Evidence</summary>
    <div class="topline">
      <div class="topline-item"><span class="brief-label">Policies</span><strong>{h(policy_summary.get("policies", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Rules</span><strong>{h(policy_summary.get("rules", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Evaluations</span><strong>{h(policy_summary.get("policy_evaluations", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">OPA/Rego</span><strong>{h(policy_summary.get("opa_rego_evaluations", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Cedar</span><strong>{h(policy_summary.get("cedar_evaluations", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Gaps</span><strong>{h(policy_summary.get("gaps", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Rule risks</span><strong>{h(policy_summary.get("policy_rule_risks", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Unmatched rules</span><strong>{h(policy_summary.get("unmatched_policy_rules", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Ineffective controls</span><strong>{h(policy_summary.get("ineffective_control_rules", 0))}</strong></div>
    </div>
    <div class="guide-columns">
      <div>
        <h3>Evaluations</h3>
        <ul>{policy_evaluations}</ul>
      </div>
      <div>
        <h3>Evaluation gaps</h3>
        <ul>{policy_gaps}</ul>
      </div>
      <div>
        <h3>Decision counts</h3>
        <ul>
          <li>Allow: {h(policy_summary.get("allow", 0))}</li>
          <li>Approval required: {h(policy_summary.get("approval_required", 0))}</li>
          <li>Deny: {h(policy_summary.get("deny", 0))}</li>
          <li>Unknown: {h(policy_summary.get("unknown", 0))}</li>
        </ul>
      </div>
      <div>
        <h3>Policy rule risks</h3>
        <ul>{policy_rule_risks}</ul>
      </div>
    </div>
  </details>
  <details id="offline-control-analysis" class="secondary-panel">
    <summary>Offline Execution-Layer Controls</summary>
    <div class="topline">
      <div class="topline-item"><span class="brief-label">Dangerous tools</span><strong>{h(offline_summary.get("dangerous_tools", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Generic tools</span><strong>{h(offline_summary.get("generic_tools", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Control rows</span><strong>{h(offline_summary.get("agent_tool_controls", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Missing controls</span><strong>{h(offline_summary.get("tools_missing_required_controls", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Prompt-boundary risks</span><strong>{h(offline_summary.get("prompt_boundary_risks", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Missing audit logging</span><strong>{h(offline_summary.get("missing_audit_logging", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Control coverage</span><strong>{h(offline_summary.get("control_coverage_percent", 100))}%</strong></div>
      <div class="topline-item"><span class="brief-label">Roadmap items</span><strong>{h(offline_summary.get("roadmap_items", 0))}</strong></div>
    </div>
    <div class="guide-columns">
      <div>
        <h3>Offline remediation roadmap</h3>
        <ul>{offline_roadmap}</ul>
      </div>
      <div>
        <h3>Generic tools</h3>
        <ul>{offline_generic_tools}</ul>
      </div>
      <div>
        <h3>Missing offline controls</h3>
        <ul>{offline_control_gaps}</ul>
      </div>
      <div>
        <h3>Prompt security boundaries</h3>
        <ul>{offline_prompt_boundaries}</ul>
      </div>
    </div>
  </details>
  <details id="privacy-analysis" class="secondary-panel">
    <summary>Data And Privacy Evidence</summary>
    <div class="topline">
      <div class="topline-item"><span class="brief-label">Data sources</span><strong>{h(privacy_summary.get("data_sources", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Classified sources</span><strong>{h(privacy_summary.get("classified_data_sources", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Classification gaps</span><strong>{h(privacy_summary.get("classification_gaps", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Memory retention gaps</span><strong>{h(privacy_summary.get("memory_retention_gaps", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Findings touching regulated data</span><strong>{h(privacy_summary.get("findings_touching_regulated_data", 0))}</strong></div>
    </div>
    <div class="guide-columns">
      <div>
        <h3>Data exposures</h3>
        <ul>{privacy_exposures}</ul>
      </div>
      <div>
        <h3>Classification gaps</h3>
        <ul>{privacy_classification_gaps}</ul>
      </div>
      <div>
        <h3>Memory retention</h3>
        <ul>{privacy_memory_retention}</ul>
      </div>
    </div>
  </details>
  <details id="iam-analysis" class="secondary-panel">
    <summary>IAM And Binding Coverage</summary>
    <div class="topline">
      <div class="topline-item"><span class="brief-label">Agent-tool bindings</span><strong>{h(iam_summary.get("agent_tool_bindings", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Explicit</span><strong>{h(iam_summary.get("explicit_bindings", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Inferred</span><strong>{h(iam_summary.get("inferred_bindings", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Ambiguous</span><strong>{h(iam_summary.get("ambiguous_bindings", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Unused identities</span><strong>{h(iam_summary.get("unused_identities", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Unused permissions</span><strong>{h(iam_summary.get("unused_permissions", 0))}</strong></div>
    </div>
    <div class="guide-columns">
      <div>
        <h3>Binding coverage</h3>
        <ul>{iam_bindings}</ul>
      </div>
      <div>
        <h3>Unused identities</h3>
        <ul>{iam_unused_identities}</ul>
        <h3>Unused permissions</h3>
        <ul>{iam_unused_permissions}</ul>
      </div>
      <div>
        <h3>Least-privilege suggestions</h3>
        <ul>{iam_suggestions}</ul>
      </div>
    </div>
  </details>
  <details id="runtime-reconstruction" class="secondary-panel">
    <summary>Runtime Reconstruction</summary>
    <div class="topline">
      <div class="topline-item"><span class="brief-label">Event quality</span><strong>{h(runtime_quality.get("grade", "unknown"))} ({h(runtime_quality.get("score", 0))}/100)</strong></div>
      <div class="topline-item"><span class="brief-label">Events</span><strong>{h(runtime_summary.get("events", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Sessions</span><strong>{h(runtime_summary.get("sessions", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Event-derived paths</span><strong>{h(runtime_summary.get("event_derived_paths", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Sessionless events</span><strong>{h(runtime_summary.get("sessionless_events", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Low-correlation events</span><strong>{h(runtime_summary.get("low_correlation_events", 0))}</strong></div>
      <div class="topline-item"><span class="brief-label">Diagnostics</span><strong>{h(runtime_summary.get("diagnostics", 0))}</strong></div>
    </div>
    <h3>Event-derived paths</h3>
    <ul>{runtime_paths}</ul>
    <h3>Runtime diagnostics</h3>
    <ul>{runtime_diagnostics}</ul>
  </details>
</section>
<script type="application/json" id="report-findings">{findings_json}</script>
<script type="application/json" id="report-graph">{graph_json}</script>
<script>
(() => {{
  const findings = JSON.parse(document.getElementById("report-findings").textContent || "[]");
  const graph = JSON.parse(document.getElementById("report-graph").textContent || '{{"nodes":[],"edges":[]}}');
  const findingById = Object.fromEntries(findings.map((finding) => [finding.id, finding]));
  const nodeById = Object.fromEntries((graph.nodes || []).map((node) => [node.id, node]));
  const edgeById = Object.fromEntries((graph.edges || []).map((edge) => [edge.id, edge]));
  const cards = Array.from(document.querySelectorAll(".card"));
  const ids = ["tier", "agent", "quality", "state", "owner", "environment", "risk", "data", "confidence", "observed", "gap", "control"];
  const controls = Object.fromEntries(ids.map((id) => [id, document.getElementById(`filter-${{id}}`)]));
  const selectedTitle = document.getElementById("selected-title");
  const selectedDescription = document.getElementById("selected-description");
  const selectedBadges = document.getElementById("selected-badges");
  const pathGraphPanel = document.getElementById("path-graph-panel");
  const rawJson = document.getElementById("raw-json");
  const matchCount = document.getElementById("match-count");
  const filteredEmpty = document.getElementById("filtered-empty");
  const clearFilters = document.getElementById("clear-filters");

  function replaceList(id, items, emptyText, renderItem) {{
    const list = document.getElementById(id);
    list.replaceChildren();
    const values = items && items.length ? items : [emptyText];
    for (const item of values) {{
      const li = document.createElement("li");
      if (renderItem && item !== emptyText) {{
        renderItem(li, item);
      }} else {{
        li.textContent = item;
      }}
      list.appendChild(li);
    }}
  }}

  function humanLabel(value) {{
    return String(value || "").replaceAll("_", " ").replaceAll("-", " ").replace(/\\b\\w/g, (char) => char.toUpperCase());
  }}

  function addBadge(label, className = "") {{
    const badge = document.createElement("span");
    badge.className = `badge ${{className}}`;
    badge.textContent = label;
    selectedBadges.appendChild(badge);
  }}

  function nodeClass(node) {{
    const classes = ["graph-node", `node-${{node.type || "unknown"}}`];
    if (node.type === "unknown" || (node.visibility_gaps || []).length) classes.push("unknown");
    if (node.type === "approval_policy") classes.push("approval-node");
    if (node.confidence === "low") classes.push("low-confidence");
    return classes.join(" ");
  }}

  function edgeClass(edge) {{
    const classes = ["graph-edge"];
    if (["event_observed", "event_allowed"].includes(edge.type)) classes.push("observed-edge");
    if (["event_blocked", "approval_present", "action_requires_approval"].includes(edge.type)) classes.push("blocked-edge");
    if (edge.confidence === "low") classes.push("low-confidence");
    return classes.join(" ");
  }}

  function renderNode(nodeId) {{
    const graphNode = nodeById[nodeId] || {{id: nodeId, type: "unknown", label: nodeId, confidence: "low"}};
    const node = document.createElement("div");
    node.className = nodeClass(graphNode);
    node.title = `layer=${{graphNode.evidence_layer || "unknown"}} confidence=${{graphNode.confidence || "unknown"}}`;
    const label = document.createElement("span");
    label.textContent = graphNode.label || nodeId;
    const type = document.createElement("small");
    type.textContent = graphNode.type || "unknown";
    node.appendChild(label);
    node.appendChild(type);
    return node;
  }}

  function renderEdge(edge) {{
    const graphEdge = edge || {{}};
    const edgeEl = document.createElement("div");
    edgeEl.className = edgeClass(graphEdge);
    edgeEl.setAttribute("aria-label", graphEdge.label || graphEdge.type || "then");
    edgeEl.title = `layer=${{graphEdge.evidence_layer || "unknown"}} confidence=${{graphEdge.confidence || "unknown"}}`;
    const arrow = document.createElement("span");
    arrow.textContent = "->";
    const edgeLabel = document.createElement("small");
    edgeLabel.textContent = graphEdge.label || graphEdge.type || "then";
    edgeEl.appendChild(arrow);
    edgeEl.appendChild(edgeLabel);
    return edgeEl;
  }}

  function renderPathGraph(finding) {{
    const container = document.createDocumentFragment();
    const wrapper = document.createElement("div");
    wrapper.className = "path-graph";
    const path = finding.nodes || [];
    const pathEdges = finding.edges || [];
    if (!path.length) {{
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "No path nodes";
      return empty;
    }}
    const usedEdges = new Set();
    path.forEach((nodeId, index) => {{
      wrapper.appendChild(renderNode(nodeId));
      if (index < path.length - 1) {{
        const nextId = path[index + 1];
        const edgeId = pathEdges.find((candidate) => {{
          const graphEdge = edgeById[candidate] || {{}};
          return graphEdge.from_node === nodeId && graphEdge.to_node === nextId;
        }});
        if (edgeId) {{
          usedEdges.add(edgeId);
        }}
        wrapper.appendChild(renderEdge(edgeById[edgeId]));
      }}
    }});
    container.appendChild(wrapper);
    const supporting = pathEdges.filter((edgeId) => !usedEdges.has(edgeId) && edgeById[edgeId]);
    if (supporting.length) {{
      const supportPanel = document.createElement("div");
      supportPanel.className = "supporting-edges";
      const heading = document.createElement("h3");
      heading.textContent = "Supporting graph edges";
      supportPanel.appendChild(heading);
      for (const edgeId of supporting) {{
        const graphEdge = edgeById[edgeId];
        const row = document.createElement("div");
        row.className = "support-edge";
        const fromNode = nodeById[graphEdge.from_node] || {{label: graphEdge.from_node}};
        const toNode = nodeById[graphEdge.to_node] || {{label: graphEdge.to_node}};
        const fromLabel = document.createElement("span");
        fromLabel.textContent = fromNode.label || graphEdge.from_node;
        const toLabel = document.createElement("span");
        toLabel.textContent = toNode.label || graphEdge.to_node;
        row.appendChild(fromLabel);
        row.appendChild(renderEdge(graphEdge));
        row.appendChild(toLabel);
        supportPanel.appendChild(row);
      }}
      container.appendChild(supportPanel);
    }}
    return container;
  }}

  function selectFinding(id) {{
    const finding = findingById[id];
    if (!finding) {{
      return;
    }}
    for (const card of cards) {{
      card.classList.toggle("selected", card.dataset.findingId === id);
    }}
    selectedTitle.textContent = finding.title || "No selected attack path";
    selectedDescription.textContent = finding.description || "";
    selectedBadges.replaceChildren();
    addBadge(String(finding.tier || "informational").toUpperCase(), `tier-${{finding.tier || "informational"}}`);
    addBadge(`Score ${{finding.score || 0}}`);
    addBadge(`Raw points ${{finding.raw_points || finding.score || 0}}`);
    addBadge(`Confidence ${{finding.confidence || "unknown"}}`);
    addBadge(`Quality ${{humanLabel(finding.evidence_quality || "incomplete")}}`);
    addBadge(humanLabel(finding.path_state || "possible"));
    addBadge(`Risk ${{humanLabel(finding.risk_status || "open")}}`);
    addBadge(`Runtime ${{humanLabel((finding.runtime_observation || {{}}).state || "not_observed")}}`);
    pathGraphPanel.replaceChildren(renderPathGraph(finding));
    replaceList("path-list", finding.path || [], "No path recorded.");
    replaceList("quality-list", [
      `Evidence quality: ${{finding.evidence_quality || "incomplete"}}`,
      `Path state: ${{finding.path_state || "possible"}}`
    ], "No evidence quality recorded.");
    const acceptedRisk = finding.accepted_risk || {{}};
    replaceList("accepted-risk-list", [
      `Status: ${{finding.risk_status || "open"}}`,
      `Accepted: ${{acceptedRisk.accepted ? "yes" : "no"}}`,
      `Expired: ${{acceptedRisk.expired ? "yes" : "no"}}`,
      `Owner: ${{acceptedRisk.owner || "unknown"}}`,
      `Expires: ${{acceptedRisk.expires_at || "unspecified"}}`,
      `Ticket: ${{acceptedRisk.ticket || "none"}}`,
      `Reason: ${{acceptedRisk.reason || "not recorded"}}`
    ], "No accepted risk metadata recorded.");
    const context = finding.operational_context || {{}};
    replaceList("operational-context-list", [
      `Owner: ${{context.owner || "unknown"}}`,
      `Environment: ${{context.environment || "unknown"}}`,
      `Runtime: ${{context.runtime || "unknown"}}`,
      `Business unit: ${{context.business_unit || "unknown"}}`,
      `Policy: ${{context.approval_policy || "unknown"}}`,
      `Last observed: ${{context.last_observed_at || "not observed"}}`
    ], "No operational context recorded.");
    replaceList("evidence-list", finding.evidence || [], "No evidence recorded.");
    const runtime = finding.runtime_observation || {{}};
    replaceList("runtime-list", [
      `State: ${{runtime.state || "not_observed"}}`,
      `Events: ${{(runtime.observed_events || []).join(", ") || "none"}}`,
      `Sessions: ${{(runtime.session_ids || []).join(", ") || "none"}}`,
      `Last observed: ${{runtime.last_observed_at || "not observed"}}`,
      `Sequence confidence: ${{runtime.sequence_confidence || "low"}}`,
      `Explanation: ${{runtime.explanation || ""}}`
    ], "No runtime observation recorded.");
    replaceList("unknowns-list", finding.unknowns || [], "No unknowns recorded.");
    replaceList("visibility-gaps-list", finding.visibility_gaps || [], "No visibility gaps attached to this finding.");
    replaceList("next-evidence-list", finding.recommended_next_evidence || [], "No next evidence request recorded.");
    replaceList("blockers-list", [...(finding.blockers || []), ...(finding.controls || [])], "No blockers or controls recorded.");
    replaceList("recommendations-list", finding.recommendations || [], "No recommendations recorded.");
    const remediation = finding.remediation || {{}};
    replaceList("recommended-controls-list", remediation.recommended_controls || [], "No recommended controls recorded.");
    document.getElementById("policy-snippet").textContent = remediation.policy_snippet ? JSON.stringify(remediation.policy_snippet, null, 2) : "No suggested policy rule recorded.";
    replaceList("required-next-evidence-list", remediation.required_next_evidence || [], "No required next evidence recorded.");
    replaceList("validation-steps-list", remediation.validation_steps || [], "No validation steps recorded.");
    replaceList("dimensions-list", (finding.scoring || {{}}).dimensions || [], "No scoring dimensions recorded.", (li, item) => {{
      const strong = document.createElement("strong");
      strong.textContent = humanLabel(item.name || "");
      li.appendChild(strong);
      li.appendChild(document.createTextNode(`: ${{item.points || 0}} `));
      const span = document.createElement("span");
      span.textContent = item.evidence || "";
      li.appendChild(span);
    }});
    replaceList("caps-list", (finding.scoring || {{}}).caps || [], "No caps applied.");
    replaceList("source-files-list", finding.source_files || [], "No source files recorded.");
    rawJson.textContent = JSON.stringify(finding, null, 2);
  }}

  function applyFilters() {{
    const values = Object.fromEntries(ids.map((id) => [id, controls[id].value]));
    const query = document.getElementById("filter-search").value.trim().toLowerCase();
    let visibleCount = 0;
    for (const card of cards) {{
      const haystack = card.dataset.search || "";
      const visible =
        (!query || haystack.includes(query)) &&
        (!values.tier || card.dataset.tier === values.tier) &&
        (!values.agent || haystack.includes(values.agent)) &&
        (!values.quality || card.dataset.quality === values.quality) &&
        (!values.state || card.dataset.state === values.state) &&
        (!values.owner || card.dataset.owner === values.owner) &&
        (!values.environment || card.dataset.environment === values.environment) &&
        (!values.risk || haystack.includes(values.risk)) &&
        (!values.data || haystack.includes(values.data)) &&
        (!values.confidence || card.dataset.confidence === values.confidence) &&
        (!values.observed || card.dataset.observed === values.observed) &&
        (!values.gap || (card.dataset.gap || "").includes(values.gap)) &&
        (!values.control || card.dataset.control === values.control);
      card.hidden = !visible;
      if (visible) visibleCount += 1;
    }}
    matchCount.textContent = String(visibleCount);
    filteredEmpty.classList.toggle("hidden", visibleCount !== 0);
  }}
  for (const control of Object.values(controls)) {{
    control.addEventListener("change", applyFilters);
  }}
  document.getElementById("filter-search").addEventListener("input", applyFilters);
  clearFilters.addEventListener("click", () => {{
    document.getElementById("filter-search").value = "";
    for (const control of Object.values(controls)) {{
      control.value = "";
    }}
    applyFilters();
  }});
  for (const card of cards) {{
    card.addEventListener("click", () => selectFinding(card.dataset.findingId));
    card.addEventListener("keydown", (event) => {{
      if (event.key === "Enter" || event.key === " ") {{
        event.preventDefault();
        selectFinding(card.dataset.findingId);
      }}
    }});
  }}
}})();
</script>
</body>
</html>
"""


def write_html_report(report: dict[str, Any], path: str | Path, *, simple: bool = False) -> None:
    output_path = Path(path)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(render_html(report, simple=simple), encoding="utf-8")
    except OSError as exc:
        raise EvidenceLoadError(f"{output_path}: cannot write HTML report: {exc}") from exc
