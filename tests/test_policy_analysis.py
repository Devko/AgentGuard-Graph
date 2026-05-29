import unittest

import _helpers  # noqa: F401 - adds src/ to sys.path for local test runs
from agentguard_graph.policy_analysis import build_policy_analysis


class PolicyAnalysisTests(unittest.TestCase):
    def test_flags_broad_allow_that_shadows_specific_deny(self):
        evidence = {
            "agents": {
                "agents": [
                    {
                        "id": "coding-agent",
                        "tools": ["shell.run"],
                        "approval_policy": "agent-policy",
                        "environment": "production",
                    }
                ]
            },
            "mcp": {
                "tools": [
                    {
                        "id": "shell.run",
                        "target_system": "host",
                        "risk_tags": ["command_execution"],
                    }
                ]
            },
            "approval_policy": {
                "policies": [
                    {
                        "id": "agent-policy",
                        "rules": [
                            {
                                "id": "allow-commands",
                                "match": {"risk_tag": "command_execution"},
                                "decision": "allow",
                            },
                            {
                                "id": "deny-shell",
                                "match": {"tool": "shell.run"},
                                "decision": "deny",
                            },
                        ],
                    }
                ],
                "policy_evaluations": [],
            },
        }

        analysis = build_policy_analysis(evidence)
        risks = analysis["rule_risks"]
        risk_types = {risk["type"] for risk in risks}

        self.assertIn("broad_allow_high_risk", risk_types)
        self.assertIn("policy_rule_shadowed", risk_types)
        self.assertIn("conflicting_matching_decisions", risk_types)
        self.assertEqual(analysis["summary"]["policy_rule_risks"], len(risks))
        self.assertEqual(analysis["summary"]["shadowed_rules"], 1)
        shadow = next(risk for risk in risks if risk["type"] == "policy_rule_shadowed")
        self.assertEqual(shadow["effective_rule"], "allow-commands")
        self.assertEqual(shadow["shadowed_rule"], "deny-shell")

    def test_scoped_approval_rule_does_not_create_policy_risks(self):
        evidence = {
            "agents": {
                "agents": [
                    {
                        "id": "coding-agent",
                        "tools": ["shell.run"],
                        "approval_policy": "agent-policy",
                        "environment": "production",
                    }
                ]
            },
            "mcp": {
                "tools": [
                    {
                        "id": "shell.run",
                        "target_system": "host",
                        "risk_tags": ["command_execution"],
                    }
                ]
            },
            "approval_policy": {
                "policies": [
                    {
                        "id": "agent-policy",
                        "rules": [
                            {
                                "id": "approve-prod-shell",
                                "match": {
                                    "agent": "coding-agent",
                                    "tool": "shell.run",
                                    "environment": "production",
                                },
                                "decision": "approval_required",
                            }
                        ],
                    }
                ],
                "policy_evaluations": [],
            },
        }

        analysis = build_policy_analysis(evidence)

        self.assertEqual(analysis["summary"]["policy_rule_risks"], 0)
        self.assertEqual(analysis["rule_risks"], [])

    def test_flags_unmatched_rules_for_typoed_tool_and_stale_agent(self):
        evidence = {
            "agents": {
                "agents": [
                    {
                        "id": "coding-agent",
                        "tools": ["shell.run"],
                        "approval_policy": "agent-policy",
                        "environment": "production",
                    }
                ]
            },
            "mcp": {
                "tools": [
                    {
                        "id": "shell.run",
                        "target_system": "host",
                        "risk_tags": ["command_execution"],
                    }
                ]
            },
            "approval_policy": {
                "policies": [
                    {
                        "id": "agent-policy",
                        "rules": [
                            {
                                "id": "approve-typoed-tool",
                                "match": {"tool": "shell.rnu"},
                                "decision": "approval_required",
                            },
                            {
                                "id": "approve-retired-agent",
                                "match": {"agent": "retired-agent", "tool": "shell.run"},
                                "decision": "approval_required",
                            },
                        ],
                    }
                ],
                "policy_evaluations": [],
            },
        }

        analysis = build_policy_analysis(evidence)
        unmatched = [risk for risk in analysis["rule_risks"] if risk["type"] == "unmatched_policy_rule"]

        self.assertEqual({risk["rule"] for risk in unmatched}, {"approve-typoed-tool", "approve-retired-agent"})
        self.assertEqual(analysis["summary"]["unmatched_policy_rules"], 2)
        typoed = next(risk for risk in unmatched if risk["rule"] == "approve-typoed-tool")
        self.assertEqual(typoed["policy"], "agent-policy")
        self.assertEqual(typoed["decision"], "approval_required")
        self.assertEqual(typoed["match_keys"], ["tool"])
        self.assertIn("did not match", typoed["reason"])

    def test_flags_ineffective_control_rule_for_matched_high_risk_tool(self):
        evidence = {
            "agents": {
                "agents": [
                    {
                        "id": "coding-agent",
                        "tools": ["shell.run"],
                        "approval_policy": "agent-policy",
                        "environment": "production",
                    }
                ]
            },
            "mcp": {
                "tools": [
                    {
                        "id": "shell.run",
                        "target_system": "host",
                        "risk_tags": ["command_execution"],
                    }
                ]
            },
            "approval_policy": {
                "policies": [
                    {
                        "id": "agent-policy",
                        "rules": [
                            {
                                "id": "wrong-control",
                                "match": {"tool": "shell.run"},
                                "decision": "approval_required",
                                "controls": ["read_only_identity"],
                            }
                        ],
                    }
                ],
                "policy_evaluations": [],
            },
        }

        analysis = build_policy_analysis(evidence)
        ineffective = [risk for risk in analysis["rule_risks"] if risk["type"] == "ineffective_control_rule"]

        self.assertEqual(len(ineffective), 1)
        risk = ineffective[0]
        self.assertEqual(risk["policy"], "agent-policy")
        self.assertEqual(risk["rule"], "wrong-control")
        self.assertEqual(risk["agent"], "coding-agent")
        self.assertEqual(risk["tool"], "shell.run")
        self.assertEqual(risk["effective_decision"], "approval_required")
        self.assertEqual(risk["declared_controls"], ["approval_required", "read_only_identity"])
        self.assertIn("command_allowlist", risk["required_controls"])
        self.assertEqual(analysis["summary"]["ineffective_control_rules"], 1)


if __name__ == "__main__":
    unittest.main()
