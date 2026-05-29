import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import sample_paths, write_json
from agentguard_graph.adapters.agents import parse_agents


class AgentAdapterTests(unittest.TestCase):
    def test_agent_config_parsing(self):
        parsed = parse_agents(sample_paths("support-agent")["agents"])
        agent = parsed["agents"][0]
        self.assertEqual(agent["id"], "support-triage-agent")
        self.assertEqual(agent["autonomy"], "autonomous")
        self.assertIn("zendesk_ticket", agent["input_sources"])
        self.assertEqual(parsed["memory_stores"][0]["retention_policy"], "unknown")

    def test_agent_parser_normalizes_tool_identity_bindings(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "agentguard.json"
            write_json(
                path,
                {
                    "agents": [
                        {
                            "id": "a",
                            "tools": ["salesforce.get_contact", "gmail.send_email"],
                            "identities": ["salesforce:a", "google:a"],
                            "input_sources": [],
                            "autonomy": "unknown",
                            "tool_identity_bindings": [
                                {"tool": "salesforce.get_contact", "identity": "salesforce:a"}
                            ],
                        }
                    ],
                    "tool_identity_bindings": {"gmail.send_email": "google:a"},
                },
            )

            parsed = parse_agents(path)
            agent = parsed["agents"][0]
            self.assertEqual(
                agent["tool_identity_bindings"],
                [
                    {"agent": "a", "tool": "salesforce.get_contact", "identity": "salesforce:a"},
                    {"agent": "a", "tool": "gmail.send_email", "identity": "google:a"},
                ],
            )
            self.assertEqual(parsed["tool_identity_bindings"], [{"agent": "a", "tool": "gmail.send_email", "identity": "google:a"}])

    def test_agent_parser_normalizes_risk_acceptances(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "agentguard.json"
            write_json(
                path,
                {
                    "agents": [
                        {
                            "id": "support-agent",
                            "tools": [],
                            "identities": [],
                            "input_sources": [],
                            "autonomy": "unknown",
                        }
                    ],
                    "risk_acceptances": [
                        {
                            "id": "risk-001",
                            "status": "accepted",
                            "rule_id": "untrusted_input_to_sensitive_data_to_external_sink",
                            "agent": "support-agent",
                            "accepted_by": "appsec",
                            "reason": "Time-bound business exception.",
                            "accepted_until": "2999-12-31",
                            "ticket": "SEC-123",
                        }
                    ],
                },
            )

            parsed = parse_agents(path)
            acceptance = parsed["risk_acceptances"][0]

            self.assertEqual(acceptance["id"], "risk-001")
            self.assertEqual(acceptance["owner"], "appsec")
            self.assertEqual(acceptance["expires_at"], "2999-12-31")
            self.assertEqual(
                acceptance["scope"],
                {"rule_id": "untrusted_input_to_sensitive_data_to_external_sink", "agent": "support-agent"},
            )

    def test_agent_parser_reports_recoverable_malformed_entries(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "agentguard.json"
            write_json(
                path,
                {
                    "agents": [
                        "not-an-agent",
                        {
                            "id": "bad-agent",
                            "autonomy": "root",
                            "environment": "moon",
                            "labels": "not-labels",
                        },
                    ],
                    "input_sources": [{"trust": "internet"}, 42],
                    "memory_stores": [
                        {
                            "id": "memory",
                            "data_classes": "customer_pii",
                            "owner": "privacy",
                            "retention_period": "30 days",
                            "deletion_policy": "delete on request",
                            "source_evidence": "admin export",
                        },
                        [],
                    ],
                },
            )

            parsed = parse_agents(path)

            self.assertEqual(parsed["agents"][0]["autonomy"], "unknown")
            self.assertEqual(parsed["agents"][0]["environment"], "unknown")
            self.assertEqual(parsed["agents"][0]["labels"], {})
            self.assertEqual(parsed["memory_stores"][0]["data_classes"], ["customer_pii"])
            self.assertEqual(parsed["memory_stores"][0]["owner"], "privacy")
            self.assertEqual(parsed["memory_stores"][0]["retention_period"], "30 days")
            self.assertEqual(parsed["memory_stores"][0]["deletion_policy"], "delete on request")
            self.assertEqual(parsed["memory_stores"][0]["source_evidence"], ["admin export"])
            joined_warnings = "\n".join(parsed["warnings"])
            self.assertIn("agents[0] must be an object", joined_warnings)
            self.assertIn("labels must be an object", joined_warnings)
            self.assertIn("autonomy normalized to unknown", joined_warnings)
            self.assertIn("environment normalized to unknown", joined_warnings)
            self.assertIn("input_sources[0] is missing id", joined_warnings)
            self.assertIn("input_sources[1] must be an object", joined_warnings)
            self.assertIn("data_classes should be a list", joined_warnings)
            self.assertIn("memory_stores[1] must be an object", joined_warnings)

            bad_bindings = Path(tmp) / "bad-bindings.json"
            write_json(
                bad_bindings,
                {
                    "agents": [
                        {
                            "id": "a",
                            "tools": [],
                            "identities": [],
                            "input_sources": [],
                            "autonomy": "unknown",
                            "tool_identity_bindings": ["bad", {"tool": "missing-identity"}],
                        }
                    ],
                    "tool_identity_bindings": "bad",
                },
            )
            binding_warnings = "\n".join(parse_agents(bad_bindings)["warnings"])
            self.assertIn("tool_identity_bindings must be a list or object", binding_warnings)
            self.assertIn("agents[0].tool_identity_bindings[0] must be an object", binding_warnings)
            self.assertIn("agents[0].tool_identity_bindings[1] is missing identity", binding_warnings)


if __name__ == "__main__":
    unittest.main()
