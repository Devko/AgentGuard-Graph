import unittest

from _helpers import SRC  # noqa: F401
from agentguard_graph.models import Edge, Finding, Graph, Node, ScoreResult, ScoringDimension


class ModelTests(unittest.TestCase):
    def test_graph_deduplicates_nodes_and_serializes(self):
        graph = Graph()
        graph.add_node(Node(id="agent:a", type="agent", label="A", properties={"x": 1}, confidence="low"))
        graph.add_node(Node(id="agent:a", type="agent", label="A", properties={"y": 2}, confidence="high"))
        graph.add_edge(Edge(id="e1", from_node="a", to_node="b", type="agent_uses_tool", label="uses"))
        data = graph.to_dict()
        self.assertEqual(len(data["nodes"]), 1)
        self.assertEqual(data["nodes"][0]["properties"]["y"], 2)
        self.assertEqual(data["nodes"][0]["confidence"], "high")
        self.assertEqual(data["edges"][0]["id"], "e1")

    def test_graph_rejects_undeclared_edge_types(self):
        graph = Graph()
        with self.assertRaises(ValueError):
            graph.add_edge(Edge(id="e1", from_node="a", to_node="b", type="uses", label="uses"))

    def test_finding_to_dict_includes_scoring(self):
        score = ScoreResult(20, "low", [ScoringDimension("untrusted_input", 20, "input")])
        finding = Finding(
            id="finding-001",
            title="Title",
            description="Description",
            tier="low",
            score=20,
            confidence="medium",
            path=["a", "b"],
            nodes=["node:a", "node:b"],
            edges=["edge:a-b"],
            evidence=["source"],
            unknowns=[],
            blockers=[],
            controls=[],
            recommendations=[],
            source_files=[],
            related_events=[],
            scoring=score,
        )
        data = finding.to_dict()
        self.assertEqual(data["scoring"]["dimensions"][0]["name"], "untrusted_input")
        self.assertEqual(data["nodes"], ["node:a", "node:b"])
        self.assertIn("evidence_layer", data)
        self.assertEqual(data["observation_status"], "possible_static")
        self.assertEqual(data["risk_status"], "open")
        self.assertFalse(data["accepted_risk"]["accepted"])


if __name__ == "__main__":
    unittest.main()
