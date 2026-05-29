import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import load_report
from agentguard_graph.outputs.json_report import write_json_report


class JsonOutputTests(unittest.TestCase):
    def test_json_report_structure(self):
        report = load_report("support-agent")
        self.assertEqual(report["schema_version"], "0.1")
        self.assertIn("summary", report)
        self.assertIn("review_brief", report)
        self.assertIn("evidence_manifest", report)
        self.assertIn("evidence_guide", report)
        self.assertIn("remediation_plan", report)
        self.assertIn("runtime_reconstruction", report)
        self.assertIn("policy_analysis", report)
        self.assertIn("offline_control_analysis", report)
        self.assertIn("privacy_analysis", report)
        self.assertIn("graph", report)
        self.assertGreaterEqual(report["summary"]["findings"], 1)
        self.assertIn("primary_risk", report["review_brief"])
        self.assertIn("top_actions", report["review_brief"])
        self.assertEqual(report["evidence_manifest"]["status"], "not_provided")
        self.assertEqual(report["evidence_manifest"]["summary"]["checked_count"], 0)
        self.assertGreaterEqual(report["remediation_plan"]["summary"]["actions"], 1)
        self.assertIn("owner_rollups", report["remediation_plan"])
        self.assertIn("system_rollups", report["remediation_plan"])
        self.assertIn("category_rollups", report["remediation_plan"])
        self.assertIn("actions", report["remediation_plan"])
        remediation_action = report["remediation_plan"]["actions"][0]
        self.assertIn("owner", remediation_action)
        self.assertIn("target", remediation_action)
        self.assertIn("category", remediation_action)
        self.assertIn("possible_static", report["summary"])
        self.assertIn("observation_status", report["findings"][0])
        self.assertIn("observation_status", report["attack_paths"][0])
        for field in [
            "path_state",
            "evidence_quality",
            "runtime_observation",
            "remediation",
            "operational_context",
            "visibility_gap_priorities",
            "raw_points",
        ]:
            self.assertIn(field, report["findings"][0])
            self.assertIn(field, report["attack_paths"][0])
        self.assertTrue(report["runtime_reconstruction"]["sessions"])
        self.assertTrue(report["runtime_reconstruction"]["event_derived_paths"])
        self.assertEqual(report["runtime_reconstruction"]["event_quality"]["grade"], "clean")
        self.assertIn("diagnostics", report["runtime_reconstruction"])
        self.assertIn("evaluations", report["policy_analysis"])
        self.assertIn("rule_risks", report["policy_analysis"])
        self.assertIn("policy_rule_risks", report["policy_analysis"]["summary"])
        self.assertIn("agent_tool_controls", report["offline_control_analysis"])
        self.assertIn("roadmap", report["offline_control_analysis"])
        self.assertIn("control_coverage_percent", report["offline_control_analysis"]["summary"])
        roadmap_item = report["offline_control_analysis"]["roadmap"][0]
        self.assertIn("id", roadmap_item)
        self.assertIn("priority", roadmap_item)
        self.assertIn("category", roadmap_item)
        self.assertIn("evidence_needed", roadmap_item)
        self.assertIn("acceptance_criteria", roadmap_item)
        self.assertTrue(roadmap_item["acceptance_criteria"])
        session = report["runtime_reconstruction"]["sessions"][0]
        self.assertIn("event_ids", session)
        self.assertIn("observed_sequence", session)
        self.assertIn("event_quality", session)
        privacy = report["privacy_analysis"]
        self.assertGreaterEqual(privacy["summary"]["data_sources"], 1)
        self.assertTrue(privacy["data_exposures"])
        self.assertTrue(privacy["memory_retention"])

    def test_json_writer(self):
        report = load_report("support-agent")
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "risk.json"
            write_json_report(report, path)
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["tool"]["name"], "agentguard-graph")


if __name__ == "__main__":
    unittest.main()
