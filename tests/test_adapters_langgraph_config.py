import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from agentguard_graph.adapters.langgraph_config import parse_langgraph_config


class LangGraphConfigCollectorTests(unittest.TestCase):
    def test_langgraph_config_parsing(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "langgraph.json"
            path.write_text(
                json.dumps(
                    {
                        "graphs": {
                            "support_agent": "./src/agent.py:graph",
                            "coding_agent": {"path": "./src/coding.py:graph"},
                        },
                        "dependencies": ["."],
                        "env": ".env",
                    }
                ),
                encoding="utf-8",
            )
            parsed = parse_langgraph_config(path)
            self.assertEqual([graph["id"] for graph in parsed["graphs"]], ["support_agent", "coding_agent"])
            self.assertEqual(parsed["env_keys"], [".env"])
            self.assertIn("not tool descriptors", parsed["warnings"][0])

    def test_langgraph_list_shape_without_graphs_warns(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "langgraph.json"
            path.write_text(json.dumps({"graphs": [], "env": {"LANGSMITH_TRACING": "true"}}), encoding="utf-8")
            parsed = parse_langgraph_config(path)
            self.assertEqual(parsed["graphs"], [])
            self.assertEqual(parsed["env_keys"], ["LANGSMITH_TRACING"])
            self.assertIn("no LangGraph graph declarations", parsed["warnings"][0])

    def test_langgraph_reports_malformed_recoverable_entries(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "langgraph.json"
            path.write_text(
                json.dumps(
                    {
                        "graphs": [{"id": "empty-entry"}, "not-graph"],
                        "env": 123,
                        "dependencies": {"bad": "shape"},
                    }
                ),
                encoding="utf-8",
            )

            parsed = parse_langgraph_config(path)

            self.assertEqual(parsed["graphs"], [{"id": "empty-entry", "entrypoint": ""}])
            joined = "\n".join(parsed["warnings"])
            self.assertIn("graph empty-entry has empty entrypoint", joined)
            self.assertIn("graphs[1] must be an object", joined)
            self.assertIn("env must be an object, string, or list", joined)
            self.assertIn("dependencies must be a string or list", joined)


if __name__ == "__main__":
    unittest.main()
