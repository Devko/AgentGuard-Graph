import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from agentguard_graph.adapters.mcp_config import parse_mcp_client_config


class MCPConfigCollectorTests(unittest.TestCase):
    def test_mcp_client_config_dict_shape(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "mcp-config.json"
            path.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "workspace": {
                                "command": "mcp-shell",
                                "tools": [
                                    {
                                        "name": "shell.run",
                                        "description": "Run a shell command",
                                        "risk_tags": ["command_execution", "not_real"],
                                    }
                                ],
                            },
                            "unknown-tools": {"command": "server-without-tool-list"},
                        }
                    }
                ),
                encoding="utf-8",
            )
            parsed = parse_mcp_client_config(path)
            self.assertEqual(parsed["servers"][0]["transport"], "stdio")
            self.assertEqual(parsed["servers"][0]["tools"][0]["risk_tags"], ["command_execution"])
            self.assertIn("no tool descriptors", parsed["warnings"][0])

    def test_mcp_client_config_nested_list_shape_and_string_tools(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested.json"
            path.write_text(
                json.dumps(
                    {
                        "mcp": {
                            "servers": [
                                {
                                    "id": "github",
                                    "url": "https://mcp.example.invalid",
                                    "tools": ["github.create_pr"],
                                }
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )
            parsed = parse_mcp_client_config(path)
            self.assertEqual(parsed["servers"][0]["id"], "github")
            self.assertEqual(parsed["servers"][0]["transport"], "http")
            self.assertEqual(parsed["servers"][0]["tools"][0]["target_system"], "github")

    def test_mcp_client_config_reports_malformed_containers_and_tools(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad-mcp.json"
            path.write_text(
                json.dumps(
                    {
                        "mcpServers": "not-a-container",
                        "mcp": {"servers": [{"id": "bad-tools", "tools": {"name": "not-a-list"}}]},
                        "servers": [{"id": "mixed-tools", "tools": ["search_docs", 123]}],
                    }
                ),
                encoding="utf-8",
            )

            parsed = parse_mcp_client_config(path)

            joined_warnings = "\n".join(parsed["warnings"])
            self.assertIn("mcpServers must be an object or list", joined_warnings)
            self.assertIn("MCP server bad-tools tools must be a list", joined_warnings)
            self.assertIn("MCP server mixed-tools skipped 1 malformed tool entries", joined_warnings)
            servers = {server["id"]: server for server in parsed["servers"]}
            self.assertEqual(servers["mixed-tools"]["tools"][0]["name"], "search_docs")


if __name__ == "__main__":
    unittest.main()
