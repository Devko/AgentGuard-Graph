import unittest

from _helpers import load_sample
from agentguard_graph.graph.builder import build_graph, build_inventory
from agentguard_graph.schemas import EDGE_TYPES


class GraphBuilderTests(unittest.TestCase):
    def test_graph_node_and_edge_creation(self):
        evidence = load_sample("support-agent")
        graph, gaps = build_graph(evidence)
        self.assertIn("agent:support-triage-agent", graph.nodes)
        self.assertIn("tool:gmail.send_email", graph.nodes)
        self.assertTrue(any(edge.type == "agent_uses_tool" for edge in graph.edges.values()))
        self.assertTrue(any(gap.type == "approval_policy_gap" for gap in gaps))

    def test_edges_use_declared_vocabulary_and_provenance_fields(self):
        graph, _gaps = build_graph(load_sample("coding-agent"))
        self.assertTrue(graph.edges)
        for node in graph.nodes.values():
            self.assertIn("evidence_layer", node.to_dict())
            self.assertIn("visibility_gaps", node.to_dict())
            self.assertIn("recommended_next_evidence", node.to_dict())
        for edge in graph.edges.values():
            self.assertIn(edge.type, EDGE_TYPES)
            data = edge.to_dict()
            self.assertIn("evidence_layer", data)
            self.assertIn("visibility_gaps", data)
            self.assertIn("recommended_next_evidence", data)

    def test_inventory_creation(self):
        inventory = build_inventory(load_sample("support-agent"))
        self.assertEqual(len(inventory["agents"]), 1)
        self.assertGreaterEqual(len(inventory["tools"]), 5)

    def test_openapi_tool_creates_api_definition_edge(self):
        evidence = {
            "agents": {
                "agents": [
                    {
                        "id": "api-agent",
                        "tools": ["runCommand"],
                        "identities": [],
                        "input_sources": [],
                        "memory": [],
                        "autonomy": "unknown",
                    }
                ],
                "input_sources": [],
                "memory_stores": [],
            },
            "mcp": {"servers": [], "tools": []},
            "openapi": {
                "tools": [
                    {
                        "id": "runCommand",
                        "name": "runCommand",
                        "method": "POST",
                        "path": "/commands",
                        "security_scopes": ["oauth:commands.run"],
                        "server_urls": ["https://api.example"],
                        "api_document_id": "openapi.json",
                        "api_source_id": "openapi.json:runCommand",
                        "api_title": "Automation API",
                        "api_version": "1.0",
                        "api_source": {
                            "id": "openapi.json",
                            "title": "Automation API",
                            "version": "1.0",
                            "source_file": "openapi.json",
                            "server_urls": ["https://api.example"],
                        },
                        "request_data_classes": ["source_code"],
                        "response_data_classes": [],
                        "data_classes": ["source_code"],
                        "risk_tags": ["command_execution", "write_action"],
                        "risk_confidence": "medium",
                        "risk_source": "inferred",
                        "target_system": "unknown",
                        "source_file": "openapi.json",
                    }
                ],
                "source_file": "openapi.json",
            },
            "identity": {"identities": []},
            "data_catalog": {"data_sources": []},
            "approval_policy": {"policies": []},
            "events": {"events": []},
        }
        graph, _gaps = build_graph(evidence)
        self.assertIn("tool:runCommand", graph.nodes)
        self.assertIn("api_definition:openapi.json", graph.nodes)
        self.assertEqual(graph.nodes["tool:runCommand"].properties["security_scopes"], ["oauth:commands.run"])
        self.assertEqual(graph.nodes["tool:runCommand"].properties["data_classes"], ["source_code"])
        self.assertEqual(graph.nodes["api_definition:openapi.json"].properties["title"], "Automation API")
        self.assertTrue(any(edge.type == "api_defines_tool" for edge in graph.edges.values()))

    def test_tool_identity_binding_scopes_iam_gap_to_bound_identity(self):
        evidence = {
            "agents": {
                "agents": [
                    {
                        "id": "support-agent",
                        "tools": ["salesforce.get_contact"],
                        "identities": ["salesforce:reader", "salesforce:unused"],
                        "tool_identity_bindings": [
                            {"agent": "support-agent", "tool": "salesforce.get_contact", "identity": "salesforce:reader"}
                        ],
                        "input_sources": [],
                        "memory": [],
                        "autonomy": "unknown",
                    }
                ],
                "input_sources": [],
                "memory_stores": [],
            },
            "mcp": {
                "servers": [],
                "tools": [
                    {
                        "id": "salesforce.get_contact",
                        "name": "salesforce.get_contact",
                        "target_system": "salesforce",
                        "risk_tags": ["sensitive_read"],
                        "risk_confidence": "high",
                    }
                ],
            },
            "openapi": {"tools": []},
            "identity": {
                "identities": [
                    {
                        "id": "salesforce:reader",
                        "type": "oauth_client",
                        "target_system": "salesforce",
                        "permissions": [
                            {
                                "resource": "salesforce.Contact",
                                "actions": ["read"],
                                "data_classes": ["customer_pii"],
                                "confidence": "high",
                            }
                        ],
                    },
                    {
                        "id": "salesforce:unused",
                        "type": "oauth_client",
                        "target_system": "salesforce",
                        "permissions": [],
                    },
                ]
            },
            "data_catalog": {"data_sources": []},
            "approval_policy": {"policies": []},
            "events": {"events": []},
        }

        graph, gaps = build_graph(evidence)
        self.assertFalse(any(gap.type == "unknown_target_iam_gap" for gap in gaps))
        self.assertTrue(any(edge.type == "tool_bound_to_identity" for edge in graph.edges.values()))
        self.assertIn("tool_identity_bindings", graph.nodes["agent:support-agent"].properties)


if __name__ == "__main__":
    unittest.main()
