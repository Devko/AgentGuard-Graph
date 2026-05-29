import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from agentguard_graph.adapters.openclaw_config import parse_openclaw_config
from agentguard_graph.errors import EvidenceLoadError


class OpenClawConfigCollectorTests(unittest.TestCase):
    def test_openclaw_config_parsing(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "openclaw.json"
            path.write_text(
                json.dumps(
                    {
                        "agents": {
                            "defaults": {"tools": {"fs": {"enabled": True}}},
                            "list": [
                                {
                                    "id": "ops-agent",
                                    "runtime": "openclaw",
                                    "tools": {
                                        "exec": {"node": "local"},
                                        "allow": ["github.create_pr"],
                                    },
                                }
                            ],
                        },
                        "channels": {"slack": {"enabled": True}, "discord": {"enabled": False}},
                    }
                ),
                encoding="utf-8",
            )
            parsed = parse_openclaw_config(path)
            self.assertEqual(parsed["agents"][0]["id"], "ops-agent")
            self.assertIn("openclaw.exec", parsed["agents"][0]["tools"])
            self.assertIn("openclaw.fs", parsed["agents"][0]["tools"])
            self.assertEqual(parsed["input_sources"][0]["id"], "slack")
            tool_names = {tool["name"] for tool in parsed["tools"]}
            self.assertIn("github.create_pr", tool_names)

    def test_openclaw_yaml_is_explicitly_unsupported(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "openclaw.yaml"
            path.write_text("agents: []", encoding="utf-8")
            with self.assertRaises(EvidenceLoadError):
                parse_openclaw_config(path)

    def test_openclaw_config_reports_malformed_recoverable_entries(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "openclaw.json"
            path.write_text(
                json.dumps(
                    {
                        "agents": {
                            "defaults": {"tools": "not-a-tool-map"},
                            "list": [
                                {"id": "ops-agent", "tools": [{"allow": ["github.create_pr"]}, 123]},
                                "not-agent",
                            ],
                        },
                        "tools": [{"allow": {"bad": "shape"}}, 42],
                    }
                ),
                encoding="utf-8",
            )

            parsed = parse_openclaw_config(path)

            self.assertEqual(parsed["agents"][0]["id"], "ops-agent")
            self.assertIn("github.create_pr", parsed["agents"][0]["tools"])
            joined = "\n".join(parsed["warnings"])
            self.assertIn("agents.defaults.tools must be an object or list", joined)
            self.assertIn("agents.list[1] must be an object", joined)
            self.assertIn("tools[0].allow must be a string or list", joined)
            self.assertIn("tools[1] must be an object or string", joined)
            self.assertIn("agents[0].tools[1] must be an object or string", joined)


if __name__ == "__main__":
    unittest.main()
