import unittest

from _helpers import build_report, clone_sample, load_report
from agentguard_graph.graph.findings import _review_decision
from agentguard_graph.graph.scoring import score_path
from agentguard_graph.models import Finding, VisibilityGap
from agentguard_graph.outputs.html import render_html
from agentguard_graph.outputs.markdown import render_markdown


def finding_for_rule(report: dict, rule_id: str) -> dict:
    return next(finding for finding in report["findings"] if finding["id"].startswith("finding-") and finding["type"] and any(path["rule_id"] == rule_id and path["id"].replace("path-", "finding-", 1) == finding["id"] for path in report["attack_paths"]))


class OperationalReportSemanticsTests(unittest.TestCase):
    def test_partial_vs_full_observed_paths_are_distinct(self):
        partial = finding_for_rule(load_report("support-agent"), "untrusted_input_to_sensitive_data_to_external_sink")
        full = finding_for_rule(load_report("demo-enterprise"), "untrusted_input_to_sensitive_data_to_external_sink")

        self.assertEqual(partial["path_state"], "observed_partial")
        self.assertEqual(partial["runtime_observation"]["state"], "observed_partial")
        self.assertEqual(full["path_state"], "observed_full")
        self.assertEqual(full["runtime_observation"]["full_sequence_session"], "support-1001")

    def test_evidence_quality_levels_and_claim_language(self):
        confirmed = finding_for_rule(load_report("demo-enterprise"), "untrusted_input_to_sensitive_data_to_external_sink")
        supported = finding_for_rule(load_report("support-agent"), "untrusted_input_to_sensitive_data_to_external_sink")

        incomplete_evidence = clone_sample("coding-agent")
        incomplete_evidence["identity"]["identities"][0]["permissions"] = []
        incomplete = build_report(incomplete_evidence)
        incomplete_finding = next(finding for finding in incomplete["findings"] if finding["type"] == "visibility_gap")

        weak_evidence = clone_sample("support-agent")
        for tool in weak_evidence["mcp"]["tools"]:
            if tool.get("id") == "gmail.send_email":
                tool["risk_source"] = "inferred"
                tool["risk_confidence"] = "low"
        weak = build_report(weak_evidence)
        weak_finding = finding_for_rule(weak, "untrusted_input_to_sensitive_data_to_external_sink")

        self.assertEqual(confirmed["evidence_quality"], "confirmed")
        self.assertTrue(confirmed["title"].startswith("Confirmed path:"))
        self.assertEqual(supported["evidence_quality"], "supported")
        self.assertTrue(supported["title"].startswith("Supported path:"))
        self.assertEqual(incomplete_finding["evidence_quality"], "incomplete")
        self.assertIn("may", incomplete_finding["title"])
        self.assertEqual(weak_finding["evidence_quality"], "weak")
        self.assertTrue(weak_finding["title"].startswith("Possible risk:"))

    def test_identity_and_permission_nodes_are_in_main_paths_and_gaps(self):
        report = load_report("support-agent")
        finding = finding_for_rule(report, "untrusted_input_to_sensitive_data_to_external_sink")
        self.assertIn("identity:salesforce:support-agent-connected-app", finding["nodes"])
        self.assertTrue(any(node.startswith("permission:salesforce:support-agent-connected-app:") for node in finding["nodes"]))
        self.assertIn("identity:google:gmail-support-agent", finding["nodes"])

        missing = clone_sample("coding-agent")
        missing["identity"]["identities"][0]["permissions"] = []
        missing_report = build_report(missing)
        gap_finding = next(finding for finding in missing_report["findings"] if finding["type"] == "visibility_gap")
        self.assertTrue(any("permissions" in node for node in gap_finding["nodes"]))
        self.assertTrue(gap_finding["visibility_gaps"])

    def test_remediation_policy_snippets_cover_rule_families(self):
        demo = load_report("demo-enterprise")
        snippets = {
            finding["rule_id"] if "rule_id" in finding else path["rule_id"]: finding["remediation"].get("policy_snippet")
            for path in demo["attack_paths"]
            for finding in demo["findings"]
            if path["id"].replace("path-", "finding-", 1) == finding["id"]
        }
        for rule_id in [
            "untrusted_input_to_sensitive_data_to_external_sink",
            "financial_action_without_approval",
            "production_change_without_approval",
            "dangerous_tool_with_untrusted_input",
            "persistent_memory_sensitive_data_gap",
        ]:
            self.assertTrue(snippets[rule_id], rule_id)
        allowed_match_keys = {
            "action_class",
            "risk_tag",
            "data_classes_any",
            "target_system",
            "environment",
            "tool",
            "agent",
            "external_target",
        }
        for snippet in (snippet for snippet in snippets.values() if snippet):
            self.assertLessEqual(set(snippet.get("match", {})), allowed_match_keys)
        self.assertIn("risk_tag", snippets["dangerous_tool_with_untrusted_input"]["match"])

    def test_review_decision_logic_variants(self):
        block = load_report("support-agent")["review_decision"]
        self.assertEqual(block["decision"], "block_launch")

        needs_more = _review_decision(
            [
                Finding(
                    id="finding-incomplete",
                    title="Potential path",
                    description="",
                    tier="medium",
                    score=64,
                    confidence="medium",
                    path=[],
                    nodes=[],
                    edges=[],
                    evidence=[],
                    unknowns=[],
                    blockers=[],
                    controls=[],
                    recommendations=[],
                    source_files=[],
                    related_events=[],
                    evidence_quality="incomplete",
                    visibility_gaps=["gap-iam-agent-github"],
                )
            ],
            [
                VisibilityGap(
                    id="gap-iam-agent-github",
                    type="unknown_target_iam_gap",
                    target="agent:github",
                    reason="Missing GitHub permission export.",
                    requested_evidence="Provide GitHub App permissions.",
                    priority="high_gap",
                )
            ],
        )
        self.assertEqual(needs_more["decision"], "needs_more_evidence")

        approve = _review_decision(
            [
                Finding(
                    id="finding-high",
                    title="High supported path",
                    description="",
                    tier="high",
                    score=70,
                    confidence="high",
                    path=[],
                    nodes=[],
                    edges=[],
                    evidence=[],
                    unknowns=[],
                    blockers=[],
                    controls=["approval_required:rule"],
                    recommendations=[],
                    source_files=[],
                    related_events=[],
                    evidence_quality="supported",
                )
            ],
            [],
        )
        self.assertEqual(approve["decision"], "approve_with_conditions")

        monitor = _review_decision(
            [
                Finding(
                    id="finding-low",
                    title="Low risk",
                    description="",
                    tier="low",
                    score=25,
                    confidence="medium",
                    path=[],
                    nodes=[],
                    edges=[],
                    evidence=[],
                    unknowns=[],
                    blockers=[],
                    controls=[],
                    recommendations=[],
                    source_files=[],
                    related_events=[],
                )
            ],
            [],
        )
        self.assertEqual(monitor["decision"], "monitor_only")

    def test_accepted_risk_metadata_marks_matching_findings_and_paths(self):
        evidence = clone_sample("support-agent")
        evidence["agents"]["risk_acceptances"] = [
            {
                "id": "risk-support-001",
                "status": "accepted",
                "owner": "appsec",
                "reason": "Temporary exception while outbound redaction control is deployed.",
                "ticket": "SEC-123",
                "expires_at": "2999-12-31",
                "scope": {
                    "agent": "support-triage-agent",
                    "rule_id": "untrusted_input_to_sensitive_data_to_external_sink",
                },
            }
        ]

        report = build_report(evidence)
        finding = finding_for_rule(report, "untrusted_input_to_sensitive_data_to_external_sink")
        path = next(path for path in report["attack_paths"] if path["id"].replace("path-", "finding-", 1) == finding["id"])

        self.assertEqual(finding["risk_status"], "accepted")
        self.assertEqual(path["risk_status"], "accepted")
        self.assertTrue(finding["accepted_risk"]["accepted"])
        self.assertFalse(finding["accepted_risk"]["expired"])
        self.assertEqual(finding["accepted_risk"]["expires_at"], "2999-12-31")
        self.assertEqual(finding["accepted_risk"]["ticket"], "SEC-123")
        self.assertEqual(report["summary"]["accepted_risk_findings"], 1)

        markdown = render_markdown(report)
        self.assertIn("Accepted risk:", markdown)
        self.assertIn("Expires: 2999-12-31", markdown)

        html = render_html(report)
        self.assertIn("Accepted risk status", html)
        self.assertIn("SEC-123", html)

    def test_expired_accepted_risk_is_called_out(self):
        evidence = clone_sample("support-agent")
        evidence["agents"]["risk_acceptances"] = [
            {
                "id": "risk-support-expired",
                "status": "accepted",
                "owner": "appsec",
                "reason": "Old exception.",
                "expires_at": "2000-01-01",
                "scope": {
                    "agent": "support-triage-agent",
                    "rule_id": "untrusted_input_to_sensitive_data_to_external_sink",
                },
            }
        ]

        report = build_report(evidence)
        finding = finding_for_rule(report, "untrusted_input_to_sensitive_data_to_external_sink")

        self.assertEqual(finding["risk_status"], "acceptance_expired")
        self.assertTrue(finding["accepted_risk"]["expired"])
        self.assertEqual(report["summary"]["expired_accepted_risk_findings"], 1)
        self.assertEqual(report["review_decision"]["decision"], "needs_more_evidence")
        self.assertEqual(report["review_decision"]["label"], "Accepted risk expired")

    def test_score_caps_and_gap_priorities(self):
        score = score_path(
            {
                "untrusted_input": "untrusted",
                "external_sink": "external",
                "sensitive_data_critical": "critical",
                "missing_approval": "missing",
                "runtime_observed_allowed": "observed",
                "autonomous_agent": "auto",
                "has_sensitive_or_critical_action": True,
                "confidences": ["high"],
            }
        )
        self.assertEqual(score.score, 100)
        self.assertGreater(score.raw_points, 100)

        weak = score_path(
            {
                "untrusted_input": "untrusted",
                "external_sink": "external",
                "missing_approval": "missing",
                "has_sensitive_or_critical_action": True,
                "confidences": ["low"],
                "evidence_quality": "weak",
            }
        )
        self.assertLessEqual(weak.score, 39)

        missing = clone_sample("coding-agent")
        missing["identity"]["identities"][0]["permissions"] = []
        report = build_report(missing)
        self.assertTrue(any(gap["priority"] in {"critical_gap", "high_gap"} for gap in report["visibility_gaps"]))

    def test_outputs_show_operational_sections_and_filters(self):
        report = load_report("support-agent")
        markdown = render_markdown(report)
        html = render_html(report)

        for expected in ["Review decision:", "Evidence quality:", "Path state:", "Suggested policy rule:", "Validation steps:"]:
            self.assertIn(expected, markdown)
        self.assertIn("Review brief", markdown)
        self.assertIn("review_brief", report)
        self.assertTrue(report["review_brief"]["top_actions"])
        for expected in [
            "Evidence quality",
            "Runtime observations",
            "Review brief",
            "Missing evidence / visibility gaps",
            "Recommended controls",
            "Suggested policy",
            'id="filter-quality"',
            'id="filter-state"',
            'id="filter-owner"',
            'id="filter-environment"',
            'id="filter-gap"',
            'id="filter-control"',
            "Owner: support-platform",
            "Environment: production",
        ]:
            self.assertIn(expected, html)

    def test_evidence_collection_guide_prioritizes_security_handoff(self):
        report = load_report("support-agent")
        guide = report["evidence_guide"]

        self.assertEqual(guide["audience"], "security_review")
        self.assertTrue(guide["collection_commands"])
        self.assertTrue(any(source["kind"] == "identity_permissions" for source in guide["evidence_sources"]))
        self.assertTrue(any(source["kind"] == "runtime_events" for source in guide["evidence_sources"]))
        self.assertTrue(guide["top_missing_evidence"])
        self.assertTrue(
            any(item["priority"] in {"critical_gap", "high_gap"} for item in guide["top_missing_evidence"])
        )
        self.assertTrue(any("service account" in question.lower() for question in guide["security_team_questions"]))

        markdown = render_markdown(report)
        self.assertIn("## Evidence collection guide", markdown)
        self.assertIn("Top missing evidence:", markdown)
        self.assertIn("Collection commands:", markdown)

        html = render_html(report)
        self.assertIn('id="evidence-guide"', html)
        self.assertIn("Evidence Collection Guide", html)
        self.assertIn("Security team questions", html)

    def test_runtime_quality_reports_correlation_diagnostics(self):
        evidence = clone_sample("support-agent")
        evidence["events"]["events"] = [
            {
                "id": "evt-clean-1",
                "event_type": "agent.tool_call",
                "timestamp": "2026-05-18T10:00:00Z",
                "agent": "support-agent",
                "session_id": "support-1001",
                "tool": "salesforce.get_contact",
                "decision": "allow",
            },
            {
                "id": "evt-missing-session",
                "event_type": "agent.tool_call",
                "timestamp": "2026-05-18T10:01:00Z",
                "agent": "support-agent",
                "tool": "gmail.send_email",
                "decision": "allow",
            },
            {
                "id": "evt-missing-agent",
                "event_type": "agent.tool_call",
                "timestamp": "2026-05-18T10:02:00Z",
                "session_id": "support-1002",
                "tool": "github.create_issue",
                "decision": "allow",
            },
            {
                "id": "evt-missing-tool",
                "event_type": "agent.tool_call",
                "timestamp": "2026-05-18T10:03:00Z",
                "agent": "support-agent",
                "session_id": "support-1001",
                "decision": "allow",
            },
            {
                "id": "evt-clean-2",
                "event_type": "agent.tool_call",
                "timestamp": "2026-05-18T10:04:00Z",
                "agent": "support-agent",
                "session_id": "support-1001",
                "tool": "gmail.send_email",
                "decision": "allow",
            },
            {
                "id": "evt-inconsistent-time",
                "event_type": "agent.tool_call",
                "timestamp": "2026-05-18T09:59:00Z",
                "agent": "support-agent",
                "session_id": "support-1001",
                "tool": "gmail.send_email",
                "decision": "allow",
            },
            {
                "id": "evt-clean-3",
                "event_type": "agent.tool_call",
                "timestamp": "2026-05-18T10:05:00Z",
                "agent": "support-agent",
                "session_id": "support-1003",
                "tool": "salesforce.get_contact",
                "decision": "allow",
            },
            {
                "id": "evt-clean-4",
                "event_type": "agent.tool_call",
                "timestamp": "2026-05-18T10:06:00Z",
                "agent": "support-agent",
                "session_id": "support-1003",
                "tool": "gmail.send_email",
                "decision": "allow",
            },
        ]

        runtime = build_report(evidence)["runtime_reconstruction"]
        diagnostic_types = {diagnostic["type"] for diagnostic in runtime["diagnostics"]}

        self.assertIn("missing_session_id", diagnostic_types)
        self.assertIn("missing_agent", diagnostic_types)
        self.assertIn("missing_tool", diagnostic_types)
        self.assertIn("inconsistent_timestamp", diagnostic_types)
        self.assertEqual(runtime["summary"]["low_correlation_events"], 4)
        self.assertEqual(runtime["event_quality"]["grade"], "low_correlation")
        self.assertTrue(any(item["reason"] == "missing session_id" for item in runtime["sessionless_events"]))

    def test_privacy_analysis_surfaces_classification_and_retention_gaps(self):
        evidence = clone_sample("support-agent")
        evidence["data_catalog"]["data_sources"].append(
            {
                "id": "warehouse.unknown_table",
                "name": "Unknown Table",
                "target_system": "snowflake",
                "data_classes": [],
                "sensitivity": "unknown",
            }
        )
        evidence["agents"]["memory_stores"][0]["owner"] = "support-data"
        evidence["agents"]["memory_stores"][0]["retention_period"] = "90 days"
        evidence["agents"]["memory_stores"][0]["deletion_policy"] = "delete on request"
        report = build_report(evidence)
        privacy = report["privacy_analysis"]

        self.assertTrue(any(item["target"] == "warehouse.unknown_table" for item in privacy["classification_gaps"]))
        memory = {item["id"]: item for item in privacy["memory_retention"]}
        self.assertEqual(memory["support-vector-store"]["owner"], "support-data")
        self.assertEqual(memory["support-vector-store"]["status"], "missing")
        self.assertTrue(any("customer_pii" in item["data_classes"] for item in privacy["data_exposures"]))


if __name__ == "__main__":
    unittest.main()
