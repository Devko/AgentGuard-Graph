import unittest

from _helpers import clone_sample, load_report, load_sample
from agentguard_graph.graph.builder import build_graph
from agentguard_graph.graph.paths import analyze_attack_paths


class AttackPathTests(unittest.TestCase):
    def test_untrusted_input_sensitive_read_external_send_path(self):
        report = load_report("support-agent")
        path = report["attack_paths"][0]
        self.assertEqual(path["rule_id"], "untrusted_input_to_sensitive_data_to_external_sink")
        self.assertEqual(path["tier"], "urgent")
        self.assertIn("gmail.send_email", path["evidence_summary"])
        self.assertIn(path["observation_status"], {"possible_static", "observed_allowed", "observed_blocked"})

    def test_command_execution_path(self):
        report = load_report("coding-agent")
        rules = {path["rule_id"] for path in report["attack_paths"]}
        self.assertIn("dangerous_tool_with_untrusted_input", rules)

    def test_financial_action_without_approval(self):
        report = load_report("support-agent")
        titles = [finding["title"] for finding in report["findings"]]
        self.assertTrue(any("financial action" in title for title in titles))

    def test_production_write_without_approval(self):
        report = load_report("coding-agent")
        self.assertTrue(any(path["rule_id"] == "production_change_without_approval" for path in report["attack_paths"]))

    def test_persistent_memory_sensitive_data_gap(self):
        report = load_report("support-agent")
        self.assertTrue(any(path["rule_id"] == "persistent_memory_sensitive_data_gap" for path in report["attack_paths"]))

    def test_unknown_iam_visibility_gap(self):
        evidence = clone_sample("coding-agent")
        evidence["identity"]["identities"][0]["permissions"] = []
        graph, gaps = build_graph(evidence)
        _paths, findings, all_gaps = analyze_attack_paths(evidence, gaps)
        self.assertTrue(any(gap.type == "unknown_target_iam_gap" for gap in all_gaps))
        self.assertTrue(any(finding.finding_type == "visibility_gap" for finding in findings))

    def test_tool_identity_binding_prevents_unused_identity_from_creating_iam_gap(self):
        evidence = clone_sample("support-agent")
        agent = evidence["agents"]["agents"][0]
        agent["identities"].append("google:unused")
        agent["tool_identity_bindings"] = [
            {"agent": agent["id"], "tool": "gmail.send_email", "identity": "google:gmail-support-agent"}
        ]
        evidence["identity"]["identities"].append(
            {
                "id": "google:unused",
                "type": "oauth_client",
                "target_system": "google_workspace",
                "scopes": [],
                "permissions": [],
                "confidence": "medium",
            }
        )

        graph, gaps = build_graph(evidence)
        paths, findings, all_gaps = analyze_attack_paths(evidence, gaps)
        google_gap_id = f"gap-iam-{agent['id']}-google_workspace"
        self.assertFalse(any(gap.id == google_gap_id for gap in all_gaps))
        self.assertFalse(any(google_gap_id in finding.visibility_gaps for finding in findings))
        self.assertTrue(any(path.rule_id == "untrusted_input_to_sensitive_data_to_external_sink" for path in paths))

    def test_runtime_observed_event_raises_score(self):
        with_event = clone_sample("coding-agent")
        without_event = clone_sample("coding-agent")
        without_event["events"]["events"] = []
        graph, gaps = build_graph(with_event)
        _paths, findings_with, _all_gaps = analyze_attack_paths(with_event, gaps)
        graph, gaps = build_graph(without_event)
        _paths, findings_without, _all_gaps = analyze_attack_paths(without_event, gaps)
        with_score = next(
            finding.score
            for finding in findings_with
            if finding.scoring and any(dimension.name == "command_execution" for dimension in finding.scoring.dimensions)
        )
        without_score = next(
            finding.score
            for finding in findings_without
            if finding.scoring and any(dimension.name == "command_execution" for dimension in finding.scoring.dimensions)
        )
        self.assertGreater(with_score, without_score)

    def test_runtime_blocked_event_creates_control_evidence(self):
        evidence = clone_sample("support-agent")
        evidence["events"]["events"].append(
            {
                "id": "event-999",
                "event_type": "agent.tool_call",
                "agent": "support-triage-agent",
                "tool": "gmail.send_email",
                "decision": "blocked",
                "policy": "manual-block",
                "confidence": "high",
            }
        )
        graph, gaps = build_graph(evidence)
        _paths, findings, _all_gaps = analyze_attack_paths(evidence, gaps)
        finding = next(item for item in findings if "send externally" in item.title)
        control_names = [control.name for control in finding.scoring.controls]
        self.assertIn("blocked_runtime_event", control_names)
        self.assertEqual(finding.observation_status, "observed_blocked")

    def test_path_and_finding_ids_are_stable(self):
        first = load_report("support-agent")
        second = load_report("support-agent")
        self.assertEqual([path["id"] for path in first["attack_paths"]], [path["id"] for path in second["attack_paths"]])
        self.assertEqual([finding["id"] for finding in first["findings"]], [finding["id"] for finding in second["findings"]])
        self.assertTrue(all(path["id"].startswith("path-") for path in first["attack_paths"]))
        self.assertTrue(all(finding["id"].startswith("finding-") for finding in first["findings"]))

    def test_path_subgraph_references_resolve_to_graph_metadata(self):
        report = load_report("coding-agent")
        node_ids = {node["id"] for node in report["graph"]["nodes"]}
        edge_ids = {edge["id"] for edge in report["graph"]["edges"]}
        for finding in report["findings"]:
            self.assertTrue(finding["nodes"])
            self.assertTrue(finding["edges"])
            self.assertFalse([node for node in finding["nodes"] if node not in node_ids])
            self.assertFalse([edge for edge in finding["edges"] if edge not in edge_ids])
            self.assertIn("evidence_layer", finding)
            self.assertIn("observation_status", finding)
            self.assertIn("visibility_gaps", finding)
            self.assertIn("recommended_next_evidence", finding)

    def test_runtime_observation_statuses_are_first_class(self):
        coding = load_report("coding-agent")
        self.assertTrue(any(finding["observation_status"] == "observed_allowed" for finding in coding["findings"]))
        self.assertGreaterEqual(coding["summary"]["observed_allowed"], 1)

        support = clone_sample("support-agent")
        support["events"]["events"].append(
            {
                "id": "event-999",
                "event_type": "agent.tool_call",
                "agent": "support-triage-agent",
                "tool": "gmail.send_email",
                "decision": "blocked",
                "policy": "manual-block",
                "confidence": "high",
            }
        )
        graph, gaps = build_graph(support)
        paths, findings, _all_gaps = analyze_attack_paths(support, gaps)
        self.assertTrue(any(path.observation_status == "observed_blocked" for path in paths))
        self.assertTrue(any(finding.observation_status == "observed_blocked" for finding in findings))


if __name__ == "__main__":
    unittest.main()
