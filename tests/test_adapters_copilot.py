import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from agentguard_graph.adapters.copilot import parse_copilot_agent


class CopilotAdapterTests(unittest.TestCase):
    def test_microsoft_365_copilot_package_parsing(self):
        with TemporaryDirectory() as tmp:
            app_package = Path(tmp) / "appPackage"
            app_package.mkdir()
            (app_package / "api").mkdir()
            (app_package / "manifest.json").write_text(
                json.dumps(
                    {
                        "manifestVersion": "1.24",
                        "id": "00000000-0000-0000-0000-000000000001",
                        "copilotAgents": {
                            "declarativeAgents": [{"id": "finance-agent", "file": "declarativeAgent.json"}]
                        },
                    }
                ),
                encoding="utf-8",
            )
            (app_package / "declarativeAgent.json").write_text(
                json.dumps(
                    {
                        "version": "v1.7",
                        "name": "Finance Copilot",
                        "description": "Finance support agent",
                        "instructions": "Help finance users with invoice and customer refund questions.",
                        "capabilities": [
                            {"name": "GraphConnectors", "connections": [{"connection_id": "financeTickets"}]},
                            {"name": "CodeInterpreter"},
                        ],
                        "actions": [{"id": "financePlugin", "file": "finance-plugin.json"}],
                    }
                ),
                encoding="utf-8",
            )
            (app_package / "finance-plugin.json").write_text(
                json.dumps(
                    {
                        "schema_version": "v2.4",
                        "name_for_human": "Finance API",
                        "description_for_model": "Send customer emails and create payment refunds.",
                        "functions": [
                            {"name": "sendCustomerEmail", "description": "Send customer email message"},
                            {"name": "createRefund", "description": "Create a customer payment refund"},
                        ],
                        "runtimes": [
                            {
                                "type": "OpenApi",
                                "auth": {"type": "OAuthPluginVault", "reference_id": "finance-oauth"},
                                "spec": {"url": "api/openapi.json"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (app_package / "api" / "openapi.json").write_text(
                json.dumps({"openapi": "3.0.0", "paths": {"/refunds": {"post": {"operationId": "createRefund"}}}}),
                encoding="utf-8",
            )

            parsed = parse_copilot_agent(app_package)

            self.assertEqual(parsed["warnings"], [])
            self.assertEqual(parsed["agents"][0]["id"], "finance-agent")
            self.assertEqual(parsed["agents"][0]["runtime"], "microsoft-365-copilot")
            self.assertIn("copilot.CodeInterpreter.run_python", parsed["agents"][0]["tools"])
            self.assertIn("sendCustomerEmail", parsed["agents"][0]["tools"])
            self.assertIn("createRefund", parsed["agents"][0]["tools"])
            self.assertEqual(parsed["input_sources"][0]["id"], "microsoft_365_copilot_user_prompt")
            self.assertIn("microsoft365:user-delegated", {identity["id"] for identity in parsed["identities"]})
            self.assertIn("copilot:finance-api:oauthpluginvault", {identity["id"] for identity in parsed["identities"]})
            self.assertIn("microsoft365.graph_connectors:financeTickets", {item["id"] for item in parsed["data_sources"]})
            self.assertEqual(parsed["openapi_paths"], [str(app_package / "api" / "openapi.json")])

            tools = {tool["name"]: tool for server in parsed["mcp_servers"] for tool in server["tools"]}
            self.assertIn("command_execution", tools["copilot.CodeInterpreter.run_python"]["risk_tags"])
            self.assertIn("external_message", tools["sendCustomerEmail"]["risk_tags"])
            self.assertIn("financial_action", tools["createRefund"]["risk_tags"])

    def test_remote_mcp_plugin_tool_description(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "declarativeAgent.json"
            path.write_text(
                json.dumps(
                    {
                        "version": "v1.7",
                        "name": "Ops Copilot",
                        "instructions": "Use remote tools for incident response.",
                        "actions": [
                            {
                                "schema_version": "v2.4",
                                "name_for_human": "Remote Ops MCP",
                                "runtimes": [
                                    {
                                        "type": "RemoteMCPServer",
                                        "auth": {"type": "OAuthPluginVault", "reference_id": "ops-mcp"},
                                        "spec": {
                                            "url": "https://mcp.ops.example",
                                            "mcp_tool_description": {
                                                "tools": [
                                                    {
                                                        "name": "run_command",
                                                        "description": "Run production command",
                                                        "inputSchema": {"type": "object"},
                                                    }
                                                ]
                                            },
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            parsed = parse_copilot_agent(path)

            self.assertEqual(parsed["agents"][0]["id"], "ops-copilot")
            self.assertIn("run_command", parsed["agents"][0]["tools"])
            tools = {tool["name"]: tool for server in parsed["mcp_servers"] for tool in server["tools"]}
            self.assertIn("command_execution", tools["run_command"]["risk_tags"])
            self.assertEqual(next(server for server in parsed["mcp_servers"] if server["transport"] == "remote_mcp")["auth"], "oauthpluginvault")


if __name__ == "__main__":
    unittest.main()
