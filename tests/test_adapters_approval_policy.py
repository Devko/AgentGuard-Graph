import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import sample_paths
from _helpers import write_json
from agentguard_graph.adapters.approval_policy import evaluate_policy, parse_approval_policy


class ApprovalPolicyAdapterTests(unittest.TestCase):
    def test_approval_policy_parsing_and_matching(self):
        parsed = parse_approval_policy(sample_paths("support-agent")["approval_policy"])
        self.assertEqual(parsed["policies"][0]["id"], "support-agent-policy")
        result = evaluate_policy(
            parsed["policies"],
            "support-agent-policy",
            {"action_class": "read_action", "risk_tags": ["read_action"], "data_classes": []},
        )
        self.assertEqual(result["decision"], "allow")
        missing = evaluate_policy(
            parsed["policies"],
            "support-agent-policy",
            {"action_class": "external_message", "risk_tags": ["external_message"], "data_classes": ["customer_pii"]},
        )
        self.assertEqual(missing["decision"], "unknown")

    def test_approval_policy_controls_parse_and_match(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "approval-policy.json"
            write_json(
                path,
                {
                    "schema_version": "0.1",
                    "policies": [
                        {
                            "id": "coding-policy",
                            "rules": [
                                {
                                    "id": "shell-sandboxed",
                                    "match": {"tool": "shell.run"},
                                    "decision": "allow",
                                    "controls": ["sandbox_control", "command_allowlist"],
                                    "reason": "Shell runs in a sandbox with an allowlist",
                                }
                            ],
                        }
                    ],
                },
            )
            parsed = parse_approval_policy(path)
            self.assertEqual(parsed["policies"][0]["rules"][0]["controls"], ["sandbox_control", "command_allowlist"])
            result = evaluate_policy(parsed["policies"], "coding-policy", {"tool": "shell.run"})
            self.assertEqual(result["decision"], "allow")
            self.assertEqual(result["controls"], ["sandbox_control", "command_allowlist"])

    def test_approval_policy_parser_reports_recoverable_malformed_entries(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "approval-policy.json"
            write_json(
                path,
                {
                    "policies": [
                        "not-a-policy",
                        {"rules": "not-a-list"},
                        {
                            "id": "coding-policy",
                            "rules": [
                                [],
                                {"match": "not-a-match", "controls": "sandbox_control"},
                            ],
                        },
                    ]
                },
            )

            parsed = parse_approval_policy(path)

            policy = {item["id"]: item for item in parsed["policies"] if item["id"]}["coding-policy"]
            self.assertEqual(policy["rules"][0]["match"], {})
            self.assertEqual(policy["rules"][0]["controls"], ["sandbox_control"])
            joined_warnings = "\n".join(parsed["warnings"])
            self.assertIn("policies[0] must be an object", joined_warnings)
            self.assertIn("policies[1] is missing id", joined_warnings)
            self.assertIn("rules must be a list", joined_warnings)
            self.assertIn("rules[0] must be an object", joined_warnings)
            self.assertIn("rules[1] is missing id", joined_warnings)
            self.assertIn("match must be an object", joined_warnings)
            self.assertIn("controls should be a list", joined_warnings)


if __name__ == "__main__":
    unittest.main()
