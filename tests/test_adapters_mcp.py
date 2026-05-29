import unittest
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import sample_paths
from agentguard_graph.adapters.mcp import infer_risk_tags, parse_mcp


class MCPAdapterTests(unittest.TestCase):
    def test_mcp_tool_parsing(self):
        parsed = parse_mcp(sample_paths("support-agent")["mcp"])
        tools = {tool["id"]: tool for tool in parsed["tools"]}
        self.assertIn("gmail.send_email", tools)
        self.assertEqual(tools["gmail.send_email"]["risk_confidence"], "high")
        self.assertIn("external_message", tools["gmail.send_email"]["risk_tags"])

    def test_risk_tag_inference_from_description(self):
        tags, confidence = infer_risk_tags("send_invoice_email", "Send a payment invoice to customer")
        self.assertEqual(confidence, "medium")
        self.assertIn("external_message", tags)
        self.assertIn("financial_action", tags)

    def test_risk_tag_inference_covers_dangerous_keywords(self):
        tags, confidence = infer_risk_tags(
            "deploy_shell_delete_repo",
            "Execute a shell command, delete files, update repository code, read secret token paths",
            {"properties": {"path": {"type": "string"}}},
        )
        self.assertEqual(confidence, "medium")
        self.assertIn("command_execution", tags)
        self.assertIn("production_write", tags)
        self.assertIn("secret_access", tags)
        self.assertIn("destructive_action", tags)
        self.assertIn("repository_write", tags)
        self.assertIn("filesystem_write", tags)

    def test_empty_mcp_path_returns_empty_evidence(self):
        parsed = parse_mcp(None)
        self.assertEqual(parsed["tools"], [])
        self.assertEqual(parsed["warnings"], [])

    def test_mcp_parser_reports_malformed_servers_and_tools(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "mcp-servers.json"
            path.write_text(
                json.dumps(
                    {
                        "servers": [
                            "not-a-server",
                            {
                                "id": "github",
                                "tools": [
                                    "github.create_pr",
                                    {"name": "github.delete_branch", "risk_tags": ["destructive_action", "not_real"]},
                                    [],
                                    {"description": "missing name"},
                                ],
                            },
                            {"tools": {"name": "not-a-list"}},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            parsed = parse_mcp(path)

            servers = {server["id"]: server for server in parsed["servers"] if server["id"]}
            tool_ids = {tool["id"] for tool in parsed["tools"]}
            self.assertIn("github.create_pr", tool_ids)
            self.assertIn("github.delete_branch", tool_ids)
            self.assertEqual(
                [tool["name"] for tool in servers["github"]["tools"][:2]],
                ["github.create_pr", "github.delete_branch"],
            )
            joined_warnings = "\n".join(parsed["warnings"])
            self.assertIn("servers[0] must be an object", joined_warnings)
            self.assertIn("tools[2] must be an object or string", joined_warnings)
            self.assertIn("tools[3] is missing name", joined_warnings)
            self.assertIn("servers[2] is missing id", joined_warnings)
            self.assertIn("tools must be a list", joined_warnings)


if __name__ == "__main__":
    unittest.main()
