import unittest

from _helpers import clone_sample
from agentguard_graph.graph.builder import build_graph
from agentguard_graph.graph.paths import analyze_attack_paths
from agentguard_graph.graph.scoring import score_path


class ScoringTests(unittest.TestCase):
    def test_score_dimensions_and_tier(self):
        score = score_path(
            {
                "untrusted_input": "untrusted",
                "command_execution": "shell",
                "missing_approval": "missing",
                "has_sensitive_or_critical_action": True,
                "confidences": ["high"],
            }
        )
        self.assertEqual(score.score, 60)
        self.assertEqual(score.tier, "medium")
        self.assertEqual(score.dimensions[0].name, "untrusted_input")

    def test_approval_policy_reduces_score(self):
        no_policy = clone_sample("support-agent")
        graph, gaps = build_graph(no_policy)
        _paths, findings, _all_gaps = analyze_attack_paths(no_policy, gaps)
        urgent_score = findings[0].score

        with_policy = clone_sample("support-agent")
        with_policy["approval_policy"]["policies"][0]["rules"].append(
            {
                "id": "external-pii-requires-approval",
                "match": {"action_class": "external_message", "data_classes_any": ["customer_pii"]},
                "decision": "approval_required",
                "reason": "PII outbound requires approval",
                "source_file": "approval-policy.json",
            }
        )
        graph, gaps = build_graph(with_policy)
        _paths, findings, _all_gaps = analyze_attack_paths(with_policy, gaps)
        controlled = next(finding for finding in findings if "send externally" in finding.title)
        self.assertLess(controlled.score, urgent_score)
        self.assertIn("approval_required", ",".join(controlled.controls))

    def test_low_confidence_cap(self):
        score = score_path(
            {
                "untrusted_input": "untrusted",
                "external_sink": "external",
                "missing_approval": "missing",
                "autonomous_agent": "auto",
                "has_sensitive_or_critical_action": True,
                "confidences": ["low"],
            }
        )
        self.assertLessEqual(score.score, 64)
        self.assertTrue(score.caps)

    def test_policy_controls_reduce_dangerous_tool_score(self):
        no_controls = clone_sample("coding-agent")
        graph, gaps = build_graph(no_controls)
        _paths, findings, _all_gaps = analyze_attack_paths(no_controls, gaps)
        baseline = next(finding.score for finding in findings if "shell.run" in finding.title and "shell.run" in finding.path)

        with_controls = clone_sample("coding-agent")
        with_controls["approval_policy"]["policies"][0]["rules"][0]["controls"] = [
            "sandbox_control",
            "command_allowlist",
            "secret_denylist",
        ]
        with_controls["approval_policy"]["policies"][0]["rules"][0][
            "reason"
        ] = "Shell tool requires approval and has sandbox, allowlist, and secret denylist controls"
        graph, gaps = build_graph(with_controls)
        _paths, findings, _all_gaps = analyze_attack_paths(with_controls, gaps)
        controlled = next(
            finding for finding in findings if "shell.run" in finding.title and "shell.run" in finding.path
        )
        self.assertLess(controlled.score, baseline)
        control_names = {control.name for control in controlled.scoring.controls}
        self.assertIn("sandbox_control", control_names)
        self.assertIn("command_allowlist", control_names)
        self.assertIn("secret_denylist", control_names)


if __name__ == "__main__":
    unittest.main()
