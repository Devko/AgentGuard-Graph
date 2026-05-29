"""Markdown summary writer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..errors import EvidenceLoadError


def md_escape(value: object) -> str:
    text = str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def _more_items_message(hidden_count: int, item_label: str) -> str:
    suffix = "" if hidden_count == 1 else "s"
    return f"{hidden_count} more {item_label}{suffix} not shown."


def render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    lines: list[str] = ["# AgentGuard Graph Report", "", "## Summary", ""]
    lines.extend(
        [
            f"- Agents: {summary.get('agents', 0)}",
            f"- Tools: {summary.get('tools', 0)}",
            f"- Findings: {summary.get('findings', 0)}",
            f"- Urgent: {summary.get('urgent', 0)}",
            f"- High: {summary.get('high', 0)}",
            f"- Visibility gaps: {summary.get('visibility_gaps', 0)}",
            f"- Critical gaps: {summary.get('critical_gaps', 0)}",
            f"- Possible paths: {summary.get('possible', 0)}",
            f"- Supported paths: {summary.get('supported', 0)}",
            f"- Observed partial paths: {summary.get('observed_partial', 0)}",
            f"- Observed full paths: {summary.get('observed_full', 0)}",
            f"- Observed allowed paths: {summary.get('observed_allowed', 0)}",
            f"- Observed blocked paths: {summary.get('observed_blocked', 0)}",
            f"- Accepted risk findings: {summary.get('accepted_risk_findings', 0)}",
            f"- Expired accepted risk findings: {summary.get('expired_accepted_risk_findings', 0)}",
            f"- Explicit tool bindings: {summary.get('explicit_bindings', 0)}",
            f"- Inferred tool bindings: {summary.get('inferred_bindings', 0)}",
            f"- Ambiguous tool bindings: {summary.get('ambiguous_bindings', 0)}",
            f"- Unused identities: {summary.get('unused_identities', 0)}",
            f"- Unused permissions: {summary.get('unused_permissions', 0)}",
            f"- Policy evaluations: {summary.get('policy_evaluations', 0)}",
            f"- Policy evaluation gaps: {summary.get('policy_evaluation_gaps', 0)}",
            f"- Generic tools: {summary.get('generic_tools', 0)}",
            f"- Tools missing offline controls: {summary.get('tools_missing_required_controls', 0)}",
            f"- Prompt-boundary risks: {summary.get('prompt_boundary_risks', 0)}",
            "",
            "## Review decision",
            "",
        ]
    )
    decision = report.get("review_decision", {})
    lines.extend(
        [
            f"Review decision: {md_escape(decision.get('label', decision.get('decision', 'unknown')))}",
            "",
            f"Reason: {md_escape(decision.get('reason', ''))}",
            "",
            "Required actions:",
        ]
    )
    for action in decision.get("required_actions", []) or ["No required actions recorded."]:
        lines.append(f"- {md_escape(action)}")
    lines.extend(["", "Decision evidence:"])
    for reason in decision.get("reasons", []) or ["No decision-specific evidence recorded."]:
        lines.append(f"- {md_escape(reason)}")
    brief = report.get("review_brief", {})
    primary_risk = brief.get("primary_risk") or {}
    if brief:
        lines.extend(
            [
                "",
                "## Review brief",
                "",
                f"Evidence posture: {md_escape(brief.get('posture', 'unknown'))}",
                f"Runtime posture: {md_escape(brief.get('runtime_posture', 'unknown'))}",
            ]
        )
        if primary_risk:
            lines.extend(
                [
                    "",
                    "Primary risk:",
                    f"- Title: {md_escape(primary_risk.get('title', 'unknown'))}",
                    f"- Tier: {md_escape(primary_risk.get('tier', 'unknown'))}",
                    f"- Score: {md_escape(primary_risk.get('score', 'unknown'))}",
                    f"- Evidence quality: {md_escape(primary_risk.get('evidence_quality', 'unknown'))}",
                    f"- Path state: {md_escape(primary_risk.get('path_state', 'unknown'))}",
                    f"- Risk status: {md_escape(primary_risk.get('risk_status', 'open'))}",
                    f"- Accepted risk expires: {md_escape(primary_risk.get('accepted_risk_expires_at') or 'none')}",
                    f"- Owner: {md_escape(primary_risk.get('owner') or 'unknown')}",
                    f"- Environment: {md_escape(primary_risk.get('environment') or 'unknown')}",
                ]
            )
        lines.extend(["", "Top visibility gaps:"])
        for gap in brief.get("top_visibility_gaps", []) or ["No priority visibility gaps recorded."]:
            if isinstance(gap, dict):
                lines.append(
                    f"- {md_escape(gap.get('priority', 'medium_gap'))}: {md_escape(gap.get('type', 'unknown'))} "
                    f"on {md_escape(gap.get('target', 'unknown'))}. {md_escape(gap.get('reason', ''))}"
                )
            else:
                lines.append(f"- {md_escape(gap)}")
        lines.extend(["", "Top actions:"])
        for action in brief.get("top_actions", []) or ["No top actions recorded."]:
            lines.append(f"- {md_escape(action)}")
    evidence_manifest = report.get("evidence_manifest", {})
    if evidence_manifest:
        manifest_summary = evidence_manifest.get("summary", {})
        lines.extend(
            [
                "",
                "## Evidence manifest attestation",
                "",
                f"- Status: {md_escape(evidence_manifest.get('status', 'not_provided'))}",
                f"- Path: {md_escape(evidence_manifest.get('path') or 'not provided')}",
                f"- Checked files: {md_escape(manifest_summary.get('checked_count', 0))}",
                f"- Changed files: {md_escape(manifest_summary.get('changed_count', 0))}",
                f"- Missing files: {md_escape(manifest_summary.get('missing_count', 0))}",
                f"- Unmanifested files: {md_escape(manifest_summary.get('unmanifested_count', 0))}",
            ]
        )
        manifest_rows = []
        for item in evidence_manifest.get("changed", [])[:5]:
            fields = ", ".join(item.get("fields", [])) if isinstance(item, dict) else ""
            manifest_rows.append(f"changed: {item.get('path', 'unknown')} ({fields or 'metadata differs'})")
        for item in evidence_manifest.get("missing", [])[:5]:
            reason = f" - {item.get('reason')}" if isinstance(item, dict) and item.get("reason") else ""
            manifest_rows.append(f"missing: {item.get('path', 'unknown')}{reason}")
        for item in evidence_manifest.get("unmanifested", [])[:5]:
            manifest_rows.append(f"unmanifested: {item.get('path', 'unknown')}")
        for error in evidence_manifest.get("errors", [])[:5]:
            manifest_rows.append(f"error: {error}")
        lines.extend(["", "Manifest details:"])
        for row in manifest_rows or ["No manifest differences recorded."]:
            lines.append(f"- {md_escape(row)}")
    remediation_plan = report.get("remediation_plan", {})
    if remediation_plan:
        plan_summary = remediation_plan.get("summary", {})
        lines.extend(
            [
                "",
                "## Owner-routed remediation plan",
                "",
                f"- Actions: {md_escape(plan_summary.get('actions', 0))}",
                f"- P1: {md_escape(plan_summary.get('p1', 0))}",
                f"- P2: {md_escape(plan_summary.get('p2', 0))}",
                f"- P3: {md_escape(plan_summary.get('p3', 0))}",
                f"- Owners: {md_escape(plan_summary.get('owners', 0))}",
                f"- Systems: {md_escape(plan_summary.get('systems', 0))}",
                f"- Categories: {md_escape(plan_summary.get('categories', 0))}",
                "",
                "Owner rollup:",
            ]
        )
        for row in remediation_plan.get("owner_rollups", [])[:8] or [{"owner": "unassigned", "action_count": 0, "p1": 0}]:
            lines.append(
                f"- {md_escape(row.get('owner', 'unassigned'))}: {md_escape(row.get('action_count', 0))} "
                f"actions ({md_escape(row.get('p1', 0))} P1)"
            )
        lines.extend(["", "Priority actions:"])
        for action in remediation_plan.get("actions", [])[:12] or ["No remediation actions generated."]:
            if isinstance(action, dict):
                next_step = action.get("suggested_next_command") or action.get("requested_evidence") or "Review related evidence."
                related = ", ".join(action.get("related_finding_ids", []) + action.get("related_gap_ids", []))
                lines.append(
                    f"- {md_escape(action.get('priority', 'P2'))}: {md_escape(action.get('owner', 'unassigned'))} "
                    f"-> {md_escape(action.get('target', 'unknown'))} [{md_escape(action.get('category', 'evidence'))}] "
                    f"{md_escape(action.get('reason', ''))} Next: {md_escape(next_step)} "
                    f"Related: {md_escape(related or 'none')}"
                )
            else:
                lines.append(f"- {md_escape(action)}")
    guide = report.get("evidence_guide", {})
    if guide:
        lines.extend(["", "## Evidence collection guide", "", md_escape(guide.get("summary", "")), ""])
        lines.append("Evidence sources:")
        for source in guide.get("evidence_sources", []):
            lines.append(
                f"- {md_escape(source.get('label', source.get('kind', 'unknown')))}: "
                f"{md_escape(source.get('status', 'unknown'))} "
                f"({md_escape(source.get('count', 0))}) - {md_escape(source.get('notes', ''))}"
            )
        lines.extend(["", "Top missing evidence:"])
        for item in guide.get("top_missing_evidence", []):
            lines.append(
                f"- {md_escape(item.get('priority', 'medium_gap'))}: {md_escape(item.get('type', 'unknown'))} "
                f"on {md_escape(item.get('target', 'unknown'))}. "
                f"Request: {md_escape(item.get('requested_evidence', ''))}"
            )
        lines.extend(["", "Collection commands:"])
        for command in guide.get("collection_commands", []):
            lines.append(f"- `{md_escape(command)}`")
        lines.extend(["", "Security team questions:"])
        for question in guide.get("security_team_questions", []):
            lines.append(f"- {md_escape(question)}")
        lines.extend(["", "Recommended next inputs:"])
        for item in guide.get("recommended_next_inputs", []):
            lines.append(f"- {md_escape(item.get('file', 'unknown'))}: {md_escape(item.get('why', ''))}")
    runtime_reconstruction = report.get("runtime_reconstruction", {})
    if runtime_reconstruction:
        runtime_summary = runtime_reconstruction.get("summary", {})
        runtime_quality = runtime_reconstruction.get("event_quality", {})
        lines.extend(
            [
                "",
                "## Runtime reconstruction",
                "",
                f"- Event quality: {md_escape(runtime_quality.get('grade', 'unknown'))} ({md_escape(runtime_quality.get('score', 0))}/100)",
                f"- Events: {md_escape(runtime_summary.get('events', 0))}",
                f"- Sessions: {md_escape(runtime_summary.get('sessions', 0))}",
                f"- Event-derived paths: {md_escape(runtime_summary.get('event_derived_paths', 0))}",
                f"- Sessionless events: {md_escape(runtime_summary.get('sessionless_events', 0))}",
                f"- Low-correlation events: {md_escape(runtime_summary.get('low_correlation_events', 0))}",
                f"- Diagnostics: {md_escape(runtime_summary.get('diagnostics', 0))}",
                "",
                "Event-derived paths:",
            ]
        )
        for item in runtime_reconstruction.get("event_derived_paths", []) or ["No event-derived paths reconstructed."]:
            if isinstance(item, dict):
                lines.append(
                    f"- {md_escape(item.get('state', 'unknown'))}: {md_escape(item.get('agent', 'unknown'))} "
                    f"session {md_escape(item.get('session_id', 'unknown'))} "
                    f"tools={md_escape(' -> '.join(item.get('tools', [])))}"
                )
            else:
                lines.append(f"- {md_escape(item)}")
        diagnostics = runtime_reconstruction.get("diagnostics", [])
        lines.extend(["", "Runtime diagnostics:"])
        for diagnostic in diagnostics[:12]:
            lines.append(
                f"- {md_escape(diagnostic.get('type', 'unknown'))}: "
                f"{md_escape(diagnostic.get('event_id') or diagnostic.get('event_key', 'unknown'))}. "
                f"{md_escape(diagnostic.get('repair', ''))}"
            )
        if not diagnostics:
            lines.append("- No runtime correlation diagnostics.")
    policy_analysis = report.get("policy_analysis", {})
    if policy_analysis:
        policy_summary = policy_analysis.get("summary", {})
        lines.extend(
            [
                "",
                "## Policy evaluation evidence",
                "",
                f"- Policies: {md_escape(policy_summary.get('policies', 0))}",
                f"- Rules: {md_escape(policy_summary.get('rules', 0))}",
                f"- Policy evaluations: {md_escape(policy_summary.get('policy_evaluations', 0))}",
                f"- OPA/Rego evaluations: {md_escape(policy_summary.get('opa_rego_evaluations', 0))}",
                f"- Cedar evaluations: {md_escape(policy_summary.get('cedar_evaluations', 0))}",
                f"- Gaps: {md_escape(policy_summary.get('gaps', 0))}",
                f"- Policy rule risks: {md_escape(policy_summary.get('policy_rule_risks', 0))}",
                f"- Broad allows: {md_escape(policy_summary.get('broad_allows', 0))}",
                f"- Shadowed rules: {md_escape(policy_summary.get('shadowed_rules', 0))}",
                f"- Conflicting decisions: {md_escape(policy_summary.get('conflicting_decisions', 0))}",
                f"- Unmatched policy rules: {md_escape(policy_summary.get('unmatched_policy_rules', 0))}",
                f"- Ineffective control rules: {md_escape(policy_summary.get('ineffective_control_rules', 0))}",
                "",
                "Evaluations:",
            ]
        )
        for item in policy_analysis.get("evaluations", [])[:12] or ["No policy evaluations recorded."]:
            if isinstance(item, dict):
                lines.append(
                    f"- {md_escape(item.get('engine', 'unknown'))}: {md_escape(item.get('decision', 'unknown'))} "
                    f"match={md_escape(', '.join(item.get('match_keys', [])) or 'none')} "
                    f"source={md_escape(item.get('source_file', 'unknown'))}"
                )
            else:
                lines.append(f"- {md_escape(item)}")
        lines.extend(["", "Policy evaluation gaps:"])
        for item in policy_analysis.get("gaps", [])[:12] or ["No policy evaluation gaps recorded."]:
            if isinstance(item, dict):
                lines.append(
                    f"- {md_escape(item.get('type', 'unknown'))}: {md_escape(item.get('target', 'unknown'))}. "
                    f"{md_escape(item.get('repair', ''))}"
                )
            else:
                lines.append(f"- {md_escape(item)}")
        lines.extend(["", "Policy rule risks:"])
        for item in policy_analysis.get("rule_risks", [])[:12] or ["No policy rule risks recorded."]:
            if isinstance(item, dict):
                matching_rules = ", ".join(
                    f"{rule.get('rule', 'unknown')}={rule.get('decision', 'unknown')}"
                    for rule in item.get("matching_rules", [])[:3]
                    if isinstance(rule, dict)
                )
                lines.append(
                    f"- {md_escape(item.get('type', 'unknown'))}: {md_escape(item.get('agent', 'unknown'))} "
                    f"-> {md_escape(item.get('tool', 'unknown'))} effective={md_escape(item.get('effective_rule', 'unknown'))} "
                    f"policy={md_escape(item.get('policy', 'unknown'))} rule={md_escape(item.get('rule', item.get('effective_rule', 'unknown')))} "
                    f"decision={md_escape(item.get('effective_decision', 'unknown'))}. "
                    f"{md_escape(item.get('reason', ''))} "
                    f"Repair: {md_escape(item.get('repair', ''))} "
                    f"Matching: {md_escape(matching_rules or 'not recorded')}"
                )
            else:
                lines.append(f"- {md_escape(item)}")
    offline_control_analysis = report.get("offline_control_analysis", {})
    if offline_control_analysis:
        offline_summary = offline_control_analysis.get("summary", {})
        lines.extend(
            [
                "",
                "## Offline execution-layer controls",
                "",
                f"- Dangerous tools: {md_escape(offline_summary.get('dangerous_tools', 0))}",
                f"- Generic tools: {md_escape(offline_summary.get('generic_tools', 0))}",
                f"- Agent-tool control rows: {md_escape(offline_summary.get('agent_tool_controls', 0))}",
                f"- Tools missing required controls: {md_escape(offline_summary.get('tools_missing_required_controls', 0))}",
                f"- Prompt-boundary risks: {md_escape(offline_summary.get('prompt_boundary_risks', 0))}",
                f"- Missing audit logging: {md_escape(offline_summary.get('missing_audit_logging', 0))}",
                f"- Offline control coverage: {md_escape(offline_summary.get('control_coverage_percent', 100))}%",
                f"- Remediation roadmap items: {md_escape(offline_summary.get('roadmap_items', 0))}",
                "",
                "Offline remediation roadmap:",
            ]
        )
        roadmap_items = offline_control_analysis.get("roadmap", [])
        roadmap_limit = 12
        for item in roadmap_items[:roadmap_limit] or ["No offline remediation roadmap items recorded."]:
            if isinstance(item, dict):
                evidence_needed = "; ".join(item.get("evidence_needed", [])[:2])
                acceptance_criteria = "; ".join(item.get("acceptance_criteria", [])[:2])
                lines.append(
                    f"- {md_escape(item.get('priority', 'P2'))}: {md_escape(item.get('title', 'unknown'))} "
                    f"({md_escape(item.get('affected_count', 0))} affected). "
                    f"{md_escape(item.get('reason', ''))} Evidence: {md_escape(evidence_needed)} "
                    f"Acceptance: {md_escape(acceptance_criteria or 'not recorded')}"
                )
            else:
                lines.append(f"- {md_escape(item)}")
        hidden_roadmap_items = max(0, len(roadmap_items) - roadmap_limit)
        if hidden_roadmap_items:
            lines.append(f"- {md_escape(_more_items_message(hidden_roadmap_items, 'offline remediation roadmap item'))}")
        lines.extend(
            [
                "",
                "Generic tools:",
            ]
        )
        for item in offline_control_analysis.get("generic_tools", [])[:12] or ["No generic tool surfaces detected."]:
            if isinstance(item, dict):
                lines.append(
                    f"- {md_escape(item.get('tool', 'unknown'))}: "
                    f"{md_escape(', '.join(item.get('broad_reasons', [])) or 'broad tool surface')}"
                )
            else:
                lines.append(f"- {md_escape(item)}")
        lines.extend(["", "Missing offline controls:"])
        for item in offline_control_analysis.get("policy_control_gaps", [])[:12] or ["No missing offline control evidence recorded."]:
            if isinstance(item, dict):
                lines.append(
                    f"- {md_escape(item.get('agent', 'unknown'))} -> {md_escape(item.get('tool', 'unknown'))}: "
                    f"{md_escape(', '.join(item.get('missing_controls', [])))}. "
                    f"{md_escape(item.get('requested_evidence', ''))}"
                )
            else:
                lines.append(f"- {md_escape(item)}")
        lines.extend(["", "Prompt security boundaries:"])
        for item in offline_control_analysis.get("prompt_security_boundaries", [])[:12] or ["No prompt-language security boundary evidence detected."]:
            if isinstance(item, dict):
                lines.append(
                    f"- {md_escape(item.get('agent', 'unknown'))}: fields={md_escape(', '.join(item.get('fields', [])))} "
                    f"terms={md_escape(', '.join(item.get('matched_terms', [])))}"
                )
            else:
                lines.append(f"- {md_escape(item)}")
    privacy_analysis = report.get("privacy_analysis", {})
    if privacy_analysis:
        privacy_summary = privacy_analysis.get("summary", {})
        lines.extend(
            [
                "",
                "## Data and privacy evidence",
                "",
                f"- Data sources: {md_escape(privacy_summary.get('data_sources', 0))}",
                f"- Classified sources: {md_escape(privacy_summary.get('classified_data_sources', 0))}",
                f"- Classification gaps: {md_escape(privacy_summary.get('classification_gaps', 0))}",
                f"- Memory retention gaps: {md_escape(privacy_summary.get('memory_retention_gaps', 0))}",
                f"- Findings touching regulated data: {md_escape(privacy_summary.get('findings_touching_regulated_data', 0))}",
                "",
                "Data exposures:",
            ]
        )
        for item in privacy_analysis.get("data_exposures", [])[:12] or ["No privacy-relevant data exposures recorded."]:
            if isinstance(item, dict):
                lines.append(
                    f"- {md_escape(item.get('tier', 'unknown'))}: {md_escape(item.get('title', 'unknown'))} "
                    f"classes={md_escape(', '.join(item.get('data_classes', [])) or 'unknown')} "
                    f"categories={md_escape(', '.join(item.get('privacy_categories', [])) or 'unmapped')}"
                )
            else:
                lines.append(f"- {md_escape(item)}")
        lines.extend(["", "Classification gaps:"])
        for item in privacy_analysis.get("classification_gaps", [])[:12] or ["No classification gaps recorded."]:
            if isinstance(item, dict):
                lines.append(
                    f"- {md_escape(item.get('type', 'unknown'))}: {md_escape(item.get('target', 'unknown'))}. "
                    f"{md_escape(item.get('requested_evidence', ''))}"
                )
            else:
                lines.append(f"- {md_escape(item)}")
        lines.extend(["", "Memory retention:"])
        for item in privacy_analysis.get("memory_retention", [])[:12] or ["No memory retention evidence recorded."]:
            if isinstance(item, dict):
                lines.append(
                    f"- {md_escape(item.get('status', 'unknown'))}: {md_escape(item.get('id', 'unknown'))} "
                    f"owner={md_escape(item.get('owner') or 'unknown')} "
                    f"retention={md_escape(item.get('retention_policy', 'unknown'))} "
                    f"period={md_escape(item.get('retention_period') or 'unknown')} "
                    f"deletion={md_escape(item.get('deletion_policy') or 'unknown')}"
                )
            else:
                lines.append(f"- {md_escape(item)}")
    iam_analysis = report.get("iam_analysis", {})
    if iam_analysis:
        iam_summary = iam_analysis.get("summary", {})
        lines.extend(
            [
                "",
                "## IAM and binding coverage",
                "",
                f"- Agent-tool bindings: {md_escape(iam_summary.get('agent_tool_bindings', 0))}",
                f"- Explicit bindings: {md_escape(iam_summary.get('explicit_bindings', 0))}",
                f"- Inferred bindings: {md_escape(iam_summary.get('inferred_bindings', 0))}",
                f"- Ambiguous bindings: {md_escape(iam_summary.get('ambiguous_bindings', 0))}",
                f"- Unbound tools: {md_escape(iam_summary.get('unbound_tools', 0))}",
                f"- Unused identities: {md_escape(iam_summary.get('unused_identities', 0))}",
                f"- Unused permissions: {md_escape(iam_summary.get('unused_permissions', 0))}",
                "",
                "Binding coverage:",
            ]
        )
        for item in iam_analysis.get("binding_coverage", [])[:20]:
            lines.append(
                f"- {md_escape(item.get('binding_type', 'unknown'))}: "
                f"{md_escape(item.get('agent', 'unknown'))} -> {md_escape(item.get('tool', 'unknown'))} "
                f"target={md_escape(item.get('target_system', 'unknown'))} "
                f"identities={md_escape(', '.join(item.get('selected_identities') or item.get('candidate_identities') or [] ) or 'none')} "
                f"permissions={md_escape(item.get('permission_status', 'unknown'))}"
            )
            if item.get("ambiguous_same_target_identities"):
                lines.append(
                    f"  - ambiguous identities: {md_escape(', '.join(item.get('ambiguous_same_target_identities', [])))}"
                )
            if item.get("recommended_action"):
                lines.append(f"  - next: {md_escape(item.get('recommended_action'))}")
        lines.extend(["", "Unused identities:"])
        for item in iam_analysis.get("unused_identities", [])[:12] or ["No unused identities recorded."]:
            if isinstance(item, dict):
                lines.append(
                    f"- {md_escape(item.get('identity', 'unknown'))}: target={md_escape(item.get('target_system', 'unknown'))}. "
                    f"{md_escape(item.get('reason', ''))}"
                )
            else:
                lines.append(f"- {md_escape(item)}")
        lines.extend(["", "Unused permissions:"])
        for item in iam_analysis.get("unused_permissions", [])[:12] or ["No unused permissions recorded."]:
            if isinstance(item, dict):
                lines.append(
                    f"- {md_escape(item.get('identity', 'unknown'))} {md_escape(item.get('resource', 'unknown'))} "
                    f"{md_escape(', '.join(item.get('actions', [])))}: {md_escape(item.get('reason', ''))}"
                )
            else:
                lines.append(f"- {md_escape(item)}")
        lines.extend(["", "Least-privilege suggestions:"])
        for item in iam_analysis.get("least_privilege_suggestions", [])[:12] or ["No least-privilege suggestions recorded."]:
            if isinstance(item, dict):
                lines.append(
                    f"- {md_escape(item.get('priority', 'P2'))}: {md_escape(item.get('target_system', 'unknown'))} "
                    f"{md_escape(item.get('identity') or item.get('tool') or '')}: {md_escape(item.get('suggestion', ''))}"
                )
            else:
                lines.append(f"- {md_escape(item)}")
    lines.extend(
        [
            "",
            "## Top attack paths",
            "",
        ]
    )
    findings = sorted(report.get("findings", []), key=lambda item: (-int(item.get("score", 0)), item.get("id", "")))
    if not findings:
        lines.extend(["No attack-path findings were produced from the supplied evidence.", ""])
    for finding in findings:
        lines.extend(
            [
                f"### {md_escape(str(finding.get('tier', 'informational')).upper())}: {md_escape(finding.get('title', ''))}",
                "",
                f"Evidence quality: {md_escape(finding.get('evidence_quality', 'incomplete'))}",
                f"Path state: {md_escape(finding.get('path_state', 'possible'))}",
                f"Observation: {md_escape(finding.get('observation_status', 'possible_static'))}",
                f"Runtime observation: {md_escape((finding.get('runtime_observation') or {}).get('state', 'not_observed'))}",
                f"Risk status: {md_escape(finding.get('risk_status', 'open'))}",
                f"Score: {md_escape(finding.get('score', 0))} (raw points: {md_escape(finding.get('raw_points', finding.get('score', 0)))})",
                "",
                "Operational context:",
            ]
        )
        context = finding.get("operational_context", {})
        for key in ["owner", "environment", "runtime", "business_unit", "approval_policy", "last_observed_at"]:
            if context.get(key):
                lines.append(f"- {md_escape(key)}: {md_escape(context.get(key))}")
        accepted_risk = finding.get("accepted_risk") or {}
        if accepted_risk.get("status") not in {"", None, "open"}:
            lines.extend(
                [
                    "",
                    "Accepted risk:",
                    f"- Status: {md_escape(accepted_risk.get('status', 'open'))}",
                    f"- Owner: {md_escape(accepted_risk.get('owner') or 'unknown')}",
                    f"- Expires: {md_escape(accepted_risk.get('expires_at') or 'unspecified')}",
                    f"- Ticket: {md_escape(accepted_risk.get('ticket') or 'none')}",
                    f"- Reason: {md_escape(accepted_risk.get('reason') or 'not recorded')}",
                ]
            )
        lines.extend(
            [
                "",
                "Path:",
            ]
        )
        for index, item in enumerate(finding.get("path", [])):
            prefix = "  -> " if index else ""
            lines.append(f"{prefix}{md_escape(item)}")
        lines.extend(["", "Why this matters:", md_escape(finding.get("description", "")), "", "Evidence:"])
        for evidence in finding.get("evidence", []):
            lines.append(f"- {md_escape(evidence)}")
        lines.extend(["", "Unknowns:"])
        for unknown in finding.get("unknowns", []) or ["No unknowns recorded."]:
            lines.append(f"- {md_escape(unknown)}")
        if finding.get("blockers") or finding.get("controls"):
            lines.extend(["", "Blockers and controls:"])
            for blocker in finding.get("blockers", []):
                lines.append(f"- {md_escape(blocker)}")
            for control in finding.get("controls", []):
                lines.append(f"- {md_escape(control)}")
        lines.extend(["", "Recommended fixes:"])
        for recommendation in finding.get("recommendations", []):
            lines.append(f"- {md_escape(recommendation)}")
        remediation = finding.get("remediation", {})
        if remediation:
            lines.extend(["", "Recommended controls:"])
            for control in remediation.get("recommended_controls", []):
                lines.append(f"- {md_escape(control)}")
            if remediation.get("least_privilege_recommendation"):
                lines.extend(["", "Least privilege recommendation:", md_escape(remediation["least_privilege_recommendation"])])
            if remediation.get("policy_snippet"):
                lines.extend(["", "Suggested policy rule:", "```json"])
                lines.append(json.dumps(remediation["policy_snippet"], indent=2, sort_keys=True))
                lines.append("```")
            lines.extend(["", "Validation steps:"])
            for step in remediation.get("validation_steps", []):
                lines.append(f"- {md_escape(step)}")
        lines.append("")

    lines.extend(["## Agent inventory", ""])
    for agent in report.get("inventory", {}).get("agents", []):
        lines.append(
            f"- {md_escape(agent.get('id'))}: autonomy={md_escape(agent.get('autonomy'))}, "
            f"environment={md_escape(agent.get('environment'))}, tools={md_escape(', '.join(agent.get('tools', [])))}"
        )
    lines.extend(["", "## Tool and identity risks", ""])
    for tool in report.get("inventory", {}).get("tools", []):
        lines.append(
            f"- {md_escape(tool.get('id'))}: target={md_escape(tool.get('target_system'))}, "
            f"risk={md_escape(', '.join(tool.get('risk_tags', [])))}, confidence={md_escape(tool.get('risk_confidence'))}"
        )
    for identity in report.get("inventory", {}).get("identities", []):
        lines.append(
            f"- {md_escape(identity.get('id'))}: target={md_escape(identity.get('target_system'))}, "
            f"permissions={len(identity.get('permissions', []))}"
        )

    lines.extend(["", "## Visibility gaps", ""])
    gaps = report.get("visibility_gaps", [])
    if not gaps:
        lines.append("No visibility gaps were produced.")
    for gap in gaps:
        lines.append(
            f"- {md_escape(gap.get('priority', 'medium_gap')).upper()}: {md_escape(gap.get('type'))} "
            f"on {md_escape(gap.get('target'))}. {md_escape(gap.get('reason'))}"
        )

    event_nodes = [node for node in report.get("graph", {}).get("nodes", []) if node.get("type") == "runtime_event"]
    if event_nodes:
        lines.extend(["", "## Runtime observations", ""])
        for node in event_nodes:
            props = node.get("properties", {})
            lines.append(
                f"- {md_escape(props.get('timestamp'))}: {md_escape(props.get('event_type'))} "
                f"{md_escape(props.get('agent'))} {md_escape(props.get('tool'))} decision={md_escape(props.get('decision'))}"
            )

    lines.extend(["", "## Recommended next steps", ""])
    recommendations: list[str] = []
    for finding in findings:
        for recommendation in finding.get("recommendations", []):
            if recommendation not in recommendations:
                recommendations.append(recommendation)
    for recommendation in recommendations[:10]:
        lines.append(f"- {md_escape(recommendation)}")

    lines.extend(["", "## Appendix: evidence sources", ""])
    sources = sorted({source for finding in findings for source in finding.get("source_files", []) if source})
    if not sources:
        sources = sorted({node.get("source") for node in report.get("graph", {}).get("nodes", []) if node.get("source")})
    for source in sources:
        lines.append(f"- {md_escape(source)}")
    lines.append("")
    return "\n".join(lines)


def write_markdown_report(report: dict[str, Any], path: str | Path) -> None:
    output_path = Path(path)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(render_markdown(report), encoding="utf-8")
    except OSError as exc:
        raise EvidenceLoadError(f"{output_path}: cannot write Markdown report: {exc}") from exc
