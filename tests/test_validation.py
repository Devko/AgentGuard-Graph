import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import sample_paths, write_json
from agentguard_graph.validation.validate_inputs import load_evidence, validate_evidence


class ValidationTests(unittest.TestCase):
    def test_validate_command_catches_missing_references(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            agents = {
                "schema_version": "0.1",
                "agents": [
                    {
                        "id": "a",
                        "tools": ["missing.tool"],
                        "identities": ["missing:id"],
                        "input_sources": [],
                        "autonomy": "autonomous",
                    }
                ],
                "input_sources": [],
                "memory_stores": [],
            }
            evidence = load_evidence(agents=write_json(tmp_path / "agentguard.json", agents))
            result = validate_evidence(evidence)
            self.assertTrue(any("unknown tool" in warning for warning in result.warnings))
            self.assertTrue(any("unknown identity" in warning for warning in result.warnings))

    def test_duplicate_ids_are_errors(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            agents = {
                "schema_version": "0.1",
                "agents": [
                    {"id": "a", "tools": ["t"], "identities": [], "input_sources": [], "autonomy": "unknown"},
                    {"id": "a", "tools": ["t"], "identities": [], "input_sources": [], "autonomy": "unknown"},
                ],
            }
            evidence = load_evidence(agents=write_json(tmp_path / "agentguard.json", agents))
            result = validate_evidence(evidence)
            self.assertFalse(result.ok)
            self.assertIn("duplicate agent id: a", result.errors)

    def test_risk_acceptance_validation_checks_scope_and_expiration(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            agents = {
                "schema_version": "0.1",
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
                        "id": "risk-ok",
                        "status": "accepted",
                        "scope": {"agent": "support-agent", "rule_id": "dangerous_tool_with_untrusted_input"},
                        "reason": "Exception approved for migration window.",
                        "expires_at": "2999-12-31",
                    },
                    {
                        "id": "risk-bad",
                        "status": "maybe",
                        "scope": {},
                        "expires_at": "tomorrow",
                    },
                ],
            }

            result = validate_evidence(load_evidence(agents=write_json(tmp_path / "agentguard.json", agents)))

            joined_errors = "\n".join(result.errors)
            self.assertIn("risk acceptance risk-bad has invalid status", joined_errors)
            self.assertIn("must scope to at least one", joined_errors)
            self.assertIn("invalid expires_at", joined_errors)

    def test_sample_validation_warns_on_gaps_not_errors(self):
        evidence = load_evidence(**sample_paths("support-agent"))
        result = validate_evidence(evidence)
        self.assertTrue(result.ok)
        self.assertTrue(result.warnings)

    def test_schema_version_compatibility_warnings(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            agents = {
                "schema_version": "0.2",
                "agents": [
                    {
                        "id": "a",
                        "tools": [],
                        "identities": [],
                        "input_sources": [],
                        "autonomy": "unknown",
                    }
                ],
                "input_sources": [],
                "memory_stores": [],
            }
            mcp = {"schema_version": "legacy", "servers": [], "tools": []}
            evidence = load_evidence(
                agents=write_json(tmp_path / "agentguard.json", agents),
                mcp=write_json(tmp_path / "mcp-servers.json", mcp),
            )
            result = validate_evidence(evidence)
            self.assertTrue(result.ok)
            joined = "\n".join(result.warnings)
            self.assertIn("agentguard.json schema_version 0.2 is newer than supported 0.1", joined)
            self.assertIn("mcp-servers.json has unsupported schema_version: legacy", joined)

    def test_strict_validation_catches_missing_required_agent_fields_and_enums(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            agents = {
                "schema_version": "0.1",
                "agents": [
                    {
                        "id": "bad-agent",
                        "tools": "shell.run",
                        "autonomy": "root",
                        "environment": "prod",
                    }
                ],
            }
            evidence = load_evidence(agents=write_json(tmp_path / "agentguard.json", agents))
            result = validate_evidence(evidence)
            joined_errors = "\n".join(result.errors)
            joined_warnings = "\n".join(result.warnings)
            self.assertIn("missing required field: identities", joined_errors)
            self.assertIn("missing required field: input_sources", joined_errors)
            self.assertIn("field must be a list: tools", joined_errors)
            self.assertIn("invalid autonomy", joined_errors)
            self.assertIn("invalid environment", joined_warnings)

    def test_strict_validation_catches_policy_and_data_errors(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            policy = {
                "schema_version": "0.1",
                "policies": [{"id": "p", "rules": [{"id": "r", "match": {}, "decision": "maybe"}]}],
            }
            data_catalog = {
                "schema_version": "0.1",
                "data_sources": [{"id": "d", "data_classes": "customer_pii", "sensitivity": "super-secret"}],
            }
            evidence = load_evidence(
                approval_policy=write_json(tmp_path / "approval-policy.json", policy),
                data_catalog=write_json(tmp_path / "data-catalog.json", data_catalog),
            )
            result = validate_evidence(evidence)
            self.assertTrue(any("invalid decision" in error for error in result.errors))
            self.assertTrue(any("field must be a list: data_classes" in error for error in result.errors))
            self.assertTrue(any("invalid sensitivity" in warning for warning in result.warnings))

    def test_validation_reports_broad_visibility_and_reference_gaps(self):
        evidence = {
            "agents": {
                "agents": [
                    {
                        "tools": ["missing.tool"],
                        "identities": ["missing:identity"],
                        "input_sources": ["missing_input"],
                        "memory": ["missing_memory"],
                        "autonomy": "unknown",
                        "raw": {},
                    }
                ],
                "input_sources": [{"trust": "internet", "raw": {"trust": "internet"}}],
                "memory_stores": [
                    {
                        "id": "memory",
                        "persistence": "persistent",
                        "retention_policy": "unknown",
                        "data_classes": ["customer_pii"],
                    }
                ],
            },
            "mcp": {
                "tools": [
                    {"id": "bad-tags", "risk_tags": [], "target_system": "unknown", "raw": {"risk_tags": "bad"}},
                    {
                        "id": "sensitive",
                        "risk_tags": ["sensitive_read"],
                        "target_system": "unknown",
                        "raw": {"risk_tags": ["unknown_tag"]},
                    },
                ]
            },
            "openapi": {"tools": [], "warnings": ["openapi.json: OpenAPI version is not 3.x or is missing"]},
            "identity": {
                "identities": [
                    {"permissions": [], "raw": {}},
                    {
                        "id": "github:agent",
                        "type": "github_app",
                        "target_system": "github",
                        "scopes": "repo",
                        "permissions": [{"resource": "repo:*", "confidence": "certain"}],
                        "raw": {"id": "github:agent", "type": "github_app", "target_system": "github", "scopes": "repo"},
                    },
                    {
                        "id": "google:agent",
                        "type": "oauth_client",
                        "target_system": "google_workspace",
                        "permissions": [],
                        "raw": {"id": "google:agent", "type": "oauth_client", "target_system": "google_workspace"},
                    },
                ]
            },
            "data_catalog": {"data_sources": [{"data_classes": [], "sensitivity": "unknown", "raw": {}}]},
            "approval_policy": {
                "policies": [
                    {
                        "rules": [
                            {
                                "id": "bad-controls",
                                "match": {"agent": "missing-agent", "tool": "missing-tool", "risk_tag": ["unknown_tag"]},
                                "decision": "allow",
                                "controls": "sandbox_control",
                                "raw": {
                                    "id": "bad-controls",
                                    "match": {"agent": "missing-agent", "tool": "missing-tool", "risk_tag": ["unknown_tag"]},
                                    "decision": "allow",
                                    "controls": "sandbox_control",
                                },
                            },
                            {
                                "match": {},
                                "decision": "allow",
                                "controls": ["unknown_control"],
                                "raw": {"match": {}, "decision": "allow", "controls": ["unknown_control"]},
                            }
                        ],
                        "raw": {},
                    }
                ]
            },
            "events": {
                "events": [
                    {
                        "id": "event-1",
                        "event_type": "agent.unknown",
                        "agent": "missing-agent",
                        "tool": "missing-tool",
                        "confidence": "certain",
                    }
                ]
            },
        }
        result = validate_evidence(evidence)
        joined_errors = "\n".join(result.errors)
        joined_warnings = "\n".join(result.warnings)
        self.assertIn("agent missing required field: id", joined_errors)
        self.assertIn("input source missing required field: id", joined_errors)
        self.assertIn("identity missing required field: id", joined_errors)
        self.assertIn("field must be a list: scopes", joined_errors)
        self.assertIn("data source missing required field: id", joined_errors)
        self.assertIn("field must be a list: risk_tags", joined_errors)
        self.assertIn("approval policy missing required field: id", joined_errors)
        self.assertIn("rule missing required field: id", joined_errors)
        self.assertIn("field must be a list: controls", joined_errors)
        self.assertIn("openapi:", joined_warnings)
        self.assertIn("unknown input source", joined_warnings)
        self.assertIn("unknown memory store", joined_warnings)
        self.assertIn("invalid trust value", joined_warnings)
        self.assertIn("has target system but no permissions", joined_warnings)
        self.assertIn("invalid confidence", joined_warnings)
        self.assertIn("unknown risk tag", joined_warnings)
        self.assertIn("sensitive-looking tool has unknown data classification", joined_warnings)
        self.assertIn("persistent memory has no retention policy", joined_warnings)
        self.assertIn("references unknown agent", joined_warnings)
        self.assertIn("references unknown tool", joined_warnings)
        self.assertIn("unknown control", joined_warnings)
        self.assertIn("unknown event_type", joined_warnings)

    def test_validation_handles_malformed_nested_collections_without_crashing(self):
        evidence = {
            "agents": {
                "agents": ["not-an-agent"],
                "input_sources": "not-a-list",
                "memory_stores": [42],
                "warnings": ["agent parser warning"],
            },
            "mcp": {
                "servers": [
                    {"id": "server-a", "transport": "custom_bus", "raw": {"id": "server-a", "tools": "bad"}},
                    {"id": "server-a"},
                    {"raw": {}},
                ],
                "tools": [
                    {"id": "duplicate"},
                    {"id": "duplicate"},
                    {"id": "orphan-tool", "server_id": "missing-server", "risk_confidence": "certain"},
                    {"id": "bad-schema", "raw": {"input_schema": "bad"}},
                    {},
                    "not-a-tool",
                ],
                "warnings": ["mcp parse warning"],
            },
            "openapi": {"tools": "not-a-list", "warnings": "not-a-list"},
            "identity": {
                "identities": [
                    {"id": "github:agent", "type": "github_app", "target_system": "github", "permissions": "not-a-list"}
                ],
                "warnings": ["identity parser warning"],
            },
            "data_catalog": {"data_sources": [None], "warnings": ["data parser warning"]},
            "approval_policy": {
                "policies": [{"id": "p", "rules": "not-a-list"}, {"id": "p", "rules": []}],
                "warnings": ["policy parser warning"],
            },
            "events": {
                "events": [
                    {
                        "id": "event-1",
                        "event_type": "agent.tool_call",
                        "confidence": "high",
                        "decision": "maybe",
                        "input_trust": "internet",
                        "raw": {
                            "id": "event-1",
                            "event_type": "agent.tool_call",
                            "confidence": "high",
                            "decision": "maybe",
                            "input_trust": "internet",
                            "data_classes": "customer_pii",
                        },
                    },
                    {"id": "event-1"},
                ],
                "warnings": ["event parser warning"],
            },
        }

        result = validate_evidence(evidence)

        joined_errors = "\n".join(result.errors)
        self.assertIn("agentguard.json agents[0] must be an object", joined_errors)
        self.assertIn("agentguard.json input_sources must be a list", joined_errors)
        self.assertIn("agentguard.json memory_stores[0] must be an object", joined_errors)
        self.assertIn("mcp server server-a field must be a list: tools", joined_errors)
        self.assertIn("mcp server missing required field: id", joined_errors)
        self.assertIn("mcp-servers.json tools[5] must be an object", joined_errors)
        self.assertIn("openapi tools must be a list", joined_errors)
        self.assertIn("openapi warnings must be a list", joined_errors)
        self.assertIn("identity github:agent permissions must be a list", joined_errors)
        self.assertIn("data-catalog.json data_sources[0] must be an object", joined_errors)
        self.assertIn("approval policy p rules must be a list", joined_errors)
        self.assertIn("duplicate mcp_server id: server-a", joined_errors)
        self.assertIn("duplicate tool id: duplicate", joined_errors)
        self.assertIn("duplicate approval_policy id: p", joined_errors)
        self.assertIn("duplicate event id: event-1", joined_errors)
        self.assertIn("tool missing required field: id/name", joined_errors)
        self.assertIn("tool bad-schema field must be an object: input_schema", joined_errors)
        self.assertIn("event event-1 field must be a list: data_classes", joined_errors)
        joined_warnings = "\n".join(result.warnings)
        self.assertIn("agentguard: agent parser warning", joined_warnings)
        self.assertIn("mcp: mcp parse warning", joined_warnings)
        self.assertIn("identity: identity parser warning", joined_warnings)
        self.assertIn("data_catalog: data parser warning", joined_warnings)
        self.assertIn("approval_policy: policy parser warning", joined_warnings)
        self.assertIn("events: event parser warning", joined_warnings)
        self.assertIn("uncommon transport", joined_warnings)
        self.assertIn("references unknown MCP server", joined_warnings)
        self.assertIn("invalid risk confidence", joined_warnings)
        self.assertIn("invalid decision", joined_warnings)
        self.assertIn("invalid input_trust", joined_warnings)
        self.assertIn("missing session_id", joined_warnings)
        self.assertIn("missing timestamp", joined_warnings)

    def test_validation_reports_tool_identity_binding_reference_gaps(self):
        evidence = {
            "agents": {
                "agents": [
                    {
                        "id": "a",
                        "tools": ["salesforce.get_contact"],
                        "identities": ["google:a"],
                        "input_sources": [],
                        "autonomy": "unknown",
                        "tool_identity_bindings": [
                            {"tool": "missing.tool", "identity": "missing:identity"},
                            {"tool": "salesforce.get_contact", "identity": "google:a"},
                        ],
                    }
                ],
                "input_sources": [],
                "memory_stores": [],
            },
            "mcp": {
                "tools": [
                    {
                        "id": "salesforce.get_contact",
                        "target_system": "salesforce",
                        "risk_tags": ["sensitive_read"],
                    }
                ]
            },
            "openapi": {"tools": []},
            "identity": {
                "identities": [
                    {"id": "google:a", "type": "oauth_client", "target_system": "google_workspace", "permissions": []}
                ]
            },
            "data_catalog": {"data_sources": []},
            "approval_policy": {"policies": []},
            "events": {"events": []},
        }

        result = validate_evidence(evidence)

        joined_warnings = "\n".join(result.warnings)
        self.assertIn("binds identity to tool not listed by agent: missing.tool", joined_warnings)
        self.assertIn("binds tool to identity not listed by agent: missing:identity", joined_warnings)
        self.assertIn("binds identity to unknown tool: missing.tool", joined_warnings)
        self.assertIn("binds tool to unknown identity: missing:identity", joined_warnings)
        self.assertIn(
            "binds tool salesforce.get_contact target_system salesforce to identity google:a target_system google_workspace",
            joined_warnings,
        )


if __name__ == "__main__":
    unittest.main()
