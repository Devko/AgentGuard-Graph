import unittest

from _helpers import load_report


class SampleTests(unittest.TestCase):
    def test_support_agent_sample_produces_urgent_or_high_path(self):
        report = load_report("support-agent")
        self.assertGreaterEqual(report["summary"]["urgent"] + report["summary"]["high"], 1)
        self.assertTrue(any("support-triage-agent" in finding["title"] for finding in report["findings"]))

    def test_coding_agent_sample_produces_high_path(self):
        report = load_report("coding-agent")
        self.assertGreaterEqual(report["summary"]["urgent"] + report["summary"]["high"], 1)
        self.assertTrue(any("coding-agent" in finding["title"] for finding in report["findings"]))

    def test_enterprise_demo_sample_covers_multiple_agents_and_cases(self):
        report = load_report("demo-enterprise")
        self.assertGreaterEqual(report["summary"]["agents"], 6)
        self.assertGreaterEqual(report["summary"]["urgent"] + report["summary"]["high"], 5)
        self.assertGreaterEqual(report["summary"]["observed_allowed"], 1)
        self.assertGreaterEqual(report["summary"]["observed_blocked"], 1)
        agents = {agent["id"]: agent for agent in report["inventory"]["agents"]}
        tools = {tool["id"] for tool in report["inventory"]["tools"]}
        sessions = {session["session_id"]: session for session in report["runtime_reconstruction"]["sessions"]}
        self.assertEqual(agents["sales-copilot-agent"]["runtime"], "microsoft-365-copilot")
        self.assertIn("outlook.send_email", tools)
        self.assertIn("powerplatform.create_discount_approval", tools)
        self.assertIn("sales-4420", sessions)
        self.assertTrue(
            any(
                path["agent"] == "sales-copilot-agent"
                and path["state"] == "observed_blocked"
                and "outlook.send_email" in path["tools"]
                for path in report["runtime_reconstruction"]["event_derived_paths"]
            )
        )
        rule_ids = {path["rule_id"] for path in report["attack_paths"]}
        self.assertIn("untrusted_input_to_sensitive_data_to_external_sink", rule_ids)
        self.assertIn("dangerous_tool_with_untrusted_input", rule_ids)
        self.assertIn("financial_action_without_approval", rule_ids)
        self.assertIn("production_change_without_approval", rule_ids)
        self.assertIn("persistent_memory_sensitive_data_gap", rule_ids)
        self.assertIn("unknown_target_iam_gap", rule_ids)


if __name__ == "__main__":
    unittest.main()
