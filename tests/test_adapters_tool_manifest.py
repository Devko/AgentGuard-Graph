import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from agentguard_graph.adapters.tool_manifest import parse_tool_manifest


class ToolManifestCollectorTests(unittest.TestCase):
    def test_tool_manifest_parsing(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "langchain-tools.json"
            path.write_text(
                json.dumps(
                    {
                        "tools": [
                            {
                                "name": "github.create_pr",
                                "description": "Create a pull request",
                                "risk_tags": ["repository_write", "not_real"],
                                "target_system": "github",
                            },
                            "search_docs",
                        ],
                        "agents": [
                            {
                                "id": "coding-agent",
                                "tools": ["github.create_pr", "search_docs"],
                                "input_sources": ["pull_request_comment"],
                            }
                        ],
                        "input_sources": [
                            {
                                "id": "pull_request_comment",
                                "trust": "untrusted",
                                "description": "External PR comments",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            parsed = parse_tool_manifest(path)
            self.assertEqual(parsed["tools"][0]["risk_tags"], ["repository_write"])
            self.assertEqual(parsed["tools"][1]["target_system"], "unknown")
            self.assertEqual(parsed["agents"][0]["id"], "coding-agent")
            self.assertEqual(parsed["input_sources"][0]["trust"], "untrusted")

    def test_empty_tool_manifest_warns(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent-tools.json"
            path.write_text(json.dumps({"tools": []}), encoding="utf-8")
            parsed = parse_tool_manifest(path)
            self.assertIn("did not contain explicit tools", parsed["warnings"][0])

    def test_tool_manifest_reports_malformed_entries(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent-tools.json"
            path.write_text(
                json.dumps(
                    {
                        "tools": [
                            {"description": "missing name", "risk_tags": ["not_real"]},
                            ["not", "a", "tool"],
                        ],
                        "agents": [{"tools": "search_docs"}, "not-agent"],
                        "input_sources": [{"trust": "untrusted"}, "not-input-source"],
                    }
                ),
                encoding="utf-8",
            )

            parsed = parse_tool_manifest(path)

            joined = "\n".join(parsed["warnings"])
            self.assertIn("tools[0] is missing name", joined)
            self.assertIn("ignored unknown risk_tags: not_real", joined)
            self.assertIn("tools[1] must be an object or string", joined)
            self.assertIn("agents[0] is missing id/name", joined)
            self.assertIn("agents[1] must be an object", joined)
            self.assertIn("input_sources[0] is missing id", joined)
            self.assertIn("input_sources[1] must be an object", joined)


if __name__ == "__main__":
    unittest.main()
