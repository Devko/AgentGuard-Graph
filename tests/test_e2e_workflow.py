import contextlib
import io
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import ROOT, sample_paths
from agentguard_graph.cli import main


class EndToEndWorkflowTests(unittest.TestCase):
    def test_e2e_doc_explains_supported_input_generation(self):
        document = (ROOT / "docs" / "E2E_WORKFLOW.md").read_text(encoding="utf-8")
        for expected in [
            "Quick Recipes For Supported Producers",
            "agentguard-graph collect",
            "MCP-Based Tools",
            "OpenAPI-Backed Tools",
            "Custom, LangChain, OpenClaw, Claude-Code-Like, And Cloud Agent Platforms",
            "Identity Systems",
            "GitHub App Permissions",
            "AWS IAM Policy",
            "Kubernetes RBAC",
            "Runtime Logs And Audit Trails",
            "Portfolio Rollup",
            "agentguard-graph portfolio",
            "risk_acceptances",
            "accepted_risk",
            "agentguard-graph validate --json",
            "Do not invent high-confidence tags without evidence",
        ]:
            self.assertIn(expected, document)

    def test_ciso_developer_handoff_evidence_dir_workflow(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            project = tmp_path / "agent-project"
            project.mkdir()
            (project / ".mcp.json").write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "workspace": {
                                "command": "mcp-shell",
                                "tools": [
                                    {
                                        "name": "shell.run",
                                        "description": "Run shell commands in the workspace",
                                        "target_system": "local_workspace",
                                    }
                                ],
                            },
                            "github": {
                                "transport": "stdio",
                                "tools": [
                                    {
                                        "name": "github.create_pr",
                                        "description": "Create a pull request",
                                        "target_system": "github",
                                    }
                                ],
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            (project / "langgraph.json").write_text(
                json.dumps({"graphs": {"coding_agent": "./agent.py:graph"}, "dependencies": ["."]}),
                encoding="utf-8",
            )
            (project / "openapi.json").write_text(
                json.dumps(
                    {
                        "openapi": "3.0.0",
                        "paths": {
                            "/messages/send": {
                                "post": {
                                    "operationId": "sendCustomerMessage",
                                    "summary": "Send customer email message",
                                }
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            evidence_dir = tmp_path / "agent-evidence"
            self.assertEqual(
                main(
                    [
                        "collect",
                        "--project-dir",
                        str(project),
                        "--out",
                        str(evidence_dir),
                        "--runtime",
                        "langgraph",
                        "--environment",
                        "production",
                        "--autonomy",
                        "approval_required",
                        "--input-source",
                        "pull_request_comment:untrusted:External PR comments",
                        "--identity",
                        "github:code-agent=github_app:github",
                    ]
                ),
                0,
            )

            collector_summary = json.loads((evidence_dir / "collector-summary.json").read_text(encoding="utf-8"))
            self.assertTrue(collector_summary["discovered_inputs"]["mcp_config"])
            self.assertTrue(collector_summary["discovered_inputs"]["langgraph_config"])
            self.assertTrue(collector_summary["discovered_inputs"]["openapi"])
            self.assertTrue(any("LangGraph config declares graph entrypoints" in item for item in collector_summary["warnings"]))

            validate_stdout = io.StringIO()
            with contextlib.redirect_stdout(validate_stdout):
                self.assertEqual(main(["validate", "--json", "--evidence-dir", str(evidence_dir)]), 0)
            validation = json.loads(validate_stdout.getvalue())
            self.assertTrue(validation["ok"])
            self.assertTrue(any("has target system but no permissions" in warning for warning in validation["warnings"]))

            output_dir = tmp_path / "outputs" / "coding-agent"
            risk_json = output_dir / "agent-risk.json"
            risk_md = output_dir / "agent-risk.md"
            risk_html = output_dir / "agent-risk.html"
            self.assertEqual(
                main(
                    [
                        "scan",
                        "--evidence-dir",
                        str(evidence_dir),
                        "--out",
                        str(risk_json),
                        "--markdown",
                        str(risk_md),
                        "--html",
                        str(risk_html),
                    ]
                ),
                0,
            )
            report = json.loads(risk_json.read_text(encoding="utf-8"))
            self.assertEqual(report["inventory"]["agents"][0]["id"], "coding_agent")
            tool_ids = {tool["id"] for tool in report["inventory"]["tools"]}
            self.assertIn("shell.run", tool_ids)
            self.assertIn("github.create_pr", tool_ids)
            self.assertIn("sendCustomerMessage", tool_ids)
            self.assertTrue(report["findings"])
            self.assertTrue(risk_md.exists())
            self.assertIn("AgentGuard Graph Report", risk_html.read_text(encoding="utf-8"))

            inventory_json = output_dir / "inventory.json"
            self.assertEqual(
                main(["inventory", "--evidence-dir", str(evidence_dir), "--out", str(inventory_json)]),
                0,
            )
            inventory = json.loads(inventory_json.read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(inventory["graph"]["nodes"]), 1)

            path_id = report["attack_paths"][0]["id"]
            explain_stdout = io.StringIO()
            with contextlib.redirect_stdout(explain_stdout):
                self.assertEqual(main(["explain", "--findings", str(risk_json), "--path-id", path_id]), 0)
            self.assertIn(path_id, explain_stdout.getvalue())

    def test_explicit_collector_sources_workflow(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            claude_config = tmp_path / "claude-mcp.json"
            claude_config.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "support": {
                                "command": "support-mcp",
                                "tools": [
                                    {
                                        "name": "salesforce.get_contact",
                                        "description": "Read Salesforce contact records",
                                        "target_system": "salesforce",
                                    },
                                    {
                                        "name": "gmail.send_email",
                                        "description": "Send email to external recipients",
                                        "target_system": "google_workspace",
                                    },
                                ],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            langgraph_config = tmp_path / "langgraph.json"
            langgraph_config.write_text(
                json.dumps({"graphs": [{"id": "support_agent", "path": "./support.py:graph"}]}),
                encoding="utf-8",
            )
            api_dir = tmp_path / "api-specs"
            api_dir.mkdir()
            (api_dir / "billing.json").write_text(
                json.dumps({"openapi": "3.0.0", "paths": {"/refunds": {"post": {"operationId": "createRefund"}}}}),
                encoding="utf-8",
            )

            evidence_dir = tmp_path / "support-evidence"
            self.assertEqual(
                main(
                    [
                        "collect",
                        "--out",
                        str(evidence_dir),
                        "--agent-id",
                        "support-agent",
                        "--runtime",
                        "claude-code",
                        "--environment",
                        "production",
                        "--autonomy",
                        "autonomous",
                        "--input-source",
                        "customer_email:untrusted:Customer-controlled email",
                        "--identity",
                        "salesforce:support-agent=oauth_client:salesforce",
                        "--claude-config",
                        str(claude_config),
                        "--langgraph-config",
                        str(langgraph_config),
                        "--openapi",
                        str(api_dir),
                        "--tool",
                        "zendesk.read_ticket",
                    ]
                ),
                0,
            )
            agentguard = json.loads((evidence_dir / "agentguard.json").read_text(encoding="utf-8"))
            tools = set(agentguard["agents"][0]["tools"])
            self.assertIn("salesforce.get_contact", tools)
            self.assertIn("gmail.send_email", tools)
            self.assertIn("createRefund", tools)
            self.assertIn("zendesk.read_ticket", tools)
            self.assertEqual(agentguard["agents"][0]["autonomy"], "autonomous")

            validate_stdout = io.StringIO()
            with contextlib.redirect_stdout(validate_stdout):
                self.assertEqual(main(["validate", "--json", "--evidence-dir", str(evidence_dir)]), 0)
            self.assertTrue(json.loads(validate_stdout.getvalue())["ok"])

            risk_json = tmp_path / "risk.json"
            self.assertEqual(main(["scan", "--evidence-dir", str(evidence_dir), "--out", str(risk_json)]), 0)
            report = json.loads(risk_json.read_text(encoding="utf-8"))
            self.assertGreaterEqual(report["summary"]["tools"], 3)
            self.assertTrue(any("zendesk.read_ticket" in gap["target"] for gap in report["visibility_gaps"]))

    def test_openclaw_and_langchain_manifest_collection_workflow(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            openclaw_config = tmp_path / "openclaw.json"
            openclaw_config.write_text(
                json.dumps(
                    {
                        "agents": {
                            "list": [
                                {
                                    "id": "ops-agent",
                                    "runtime": "openclaw",
                                    "tools": {
                                        "exec": {"node": "local"},
                                        "github": {"enabled": True},
                                    },
                                }
                            ]
                        },
                        "channels": {"slack": {"enabled": True}},
                    }
                ),
                encoding="utf-8",
            )
            langchain_manifest = tmp_path / "langchain-tools.json"
            langchain_manifest.write_text(
                json.dumps(
                    {
                        "tools": [
                            {
                                "name": "secrets.read",
                                "description": "Read secret material",
                                "risk_tags": ["secret_access"],
                                "target_system": "vault",
                            }
                        ],
                        "agents": [
                            {
                                "id": "ops-agent",
                                "tools": ["secrets.read"],
                                "input_sources": ["slack"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            evidence_dir = tmp_path / "ops-evidence"
            self.assertEqual(
                main(
                    [
                        "collect",
                        "--out",
                        str(evidence_dir),
                        "--openclaw-config",
                        str(openclaw_config),
                        "--langchain-manifest",
                        str(langchain_manifest),
                        "--identity",
                        "github:ops-agent=github_app:github",
                    ]
                ),
                0,
            )
            agentguard = json.loads((evidence_dir / "agentguard.json").read_text(encoding="utf-8"))
            self.assertEqual(agentguard["agents"][0]["id"], "ops-agent")
            self.assertIn("slack", agentguard["agents"][0]["input_sources"])
            self.assertIn("secrets.read", agentguard["agents"][0]["tools"])
            self.assertIn("openclaw.exec", agentguard["agents"][0]["tools"])

            risk_json = tmp_path / "ops-risk.json"
            self.assertEqual(main(["scan", "--evidence-dir", str(evidence_dir), "--out", str(risk_json)]), 0)
            report = json.loads(risk_json.read_text(encoding="utf-8"))
            tool_ids = {tool["id"] for tool in report["inventory"]["tools"]}
            self.assertIn("secrets.read", tool_ids)
            self.assertIn("openclaw.exec", tool_ids)
            self.assertGreaterEqual(report["summary"]["high"], 1)

    def test_project_collection_with_identity_permission_exports(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            project = tmp_path / "agent-project"
            project.mkdir()
            (project / "langchain-tools.json").write_text(
                json.dumps(
                    {
                        "tools": [
                            {
                                "name": "github.create_pr",
                                "description": "Create a GitHub pull request",
                                "risk_tags": ["repository_write"],
                                "target_system": "github",
                            }
                        ],
                        "agents": [
                            {
                                "id": "coding-agent",
                                "runtime": "langchain",
                                "tools": ["github.create_pr"],
                                "identities": ["github:code-agent"],
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
            (project / "github-app-permissions.json").write_text(
                json.dumps(
                    {
                        "identity_id": "github:code-agent",
                        "permissions": {
                            "contents": "write",
                            "pull_requests": "write",
                        },
                    }
                ),
                encoding="utf-8",
            )

            evidence_dir = tmp_path / "coding-evidence"
            self.assertEqual(main(["collect", "--project-dir", str(project), "--out", str(evidence_dir)]), 0)

            validate_stdout = io.StringIO()
            with contextlib.redirect_stdout(validate_stdout):
                self.assertEqual(main(["validate", "--json", "--evidence-dir", str(evidence_dir)]), 0)
            validation = json.loads(validate_stdout.getvalue())
            self.assertTrue(validation["ok"])
            self.assertFalse(any("github:code-agent has target system but no permissions" in warning for warning in validation["warnings"]))

            identity = json.loads((evidence_dir / "identity.json").read_text(encoding="utf-8"))
            github_identity = identity["identities"][0]
            self.assertEqual(github_identity["id"], "github:code-agent")
            self.assertTrue(github_identity["permissions"])

            risk_json = tmp_path / "coding-risk.json"
            self.assertEqual(main(["scan", "--evidence-dir", str(evidence_dir), "--out", str(risk_json)]), 0)
            report = json.loads(risk_json.read_text(encoding="utf-8"))
            self.assertTrue(report["findings"])
            self.assertFalse(
                any(
                    gap["type"] == "unknown_target_iam_gap" and gap["target"] == "coding-agent:github"
                    for gap in report["visibility_gaps"]
                )
            )

    def test_init_sample_evidence_dir_workflow(self):
        with TemporaryDirectory() as tmp:
            evidence_dir = Path(tmp) / "coding-evidence"
            self.assertEqual(main(["init", "--out", str(evidence_dir), "--sample", "coding-agent"]), 0)

            validate_stdout = io.StringIO()
            with contextlib.redirect_stdout(validate_stdout):
                self.assertEqual(main(["validate", "--json", "--evidence-dir", str(evidence_dir)]), 0)
            self.assertTrue(json.loads(validate_stdout.getvalue())["ok"])

            risk_json = Path(tmp) / "coding-risk.json"
            self.assertEqual(main(["scan", "--evidence-dir", str(evidence_dir), "--out", str(risk_json)]), 0)
            report = json.loads(risk_json.read_text(encoding="utf-8"))
            self.assertGreaterEqual(report["summary"]["high"], 1)
            self.assertTrue(any(finding["observation_status"] == "observed_allowed" for finding in report["findings"]))

    def test_documented_e2e_workflow(self):
        paths = sample_paths("support-agent")
        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "outputs" / "support-agent"
            risk_json = output_dir / "agent-risk.json"
            risk_md = output_dir / "agent-risk.md"
            risk_html = output_dir / "agent-risk.html"
            inventory_json = output_dir / "inventory.json"

            validate_stdout = io.StringIO()
            with contextlib.redirect_stdout(validate_stdout):
                validate_code = main(
                    [
                        "validate",
                        "--json",
                        "--agents",
                        paths["agents"],
                        "--mcp",
                        paths["mcp"],
                        "--identity",
                        paths["identity"],
                        "--data-catalog",
                        paths["data_catalog"],
                        "--approval-policy",
                        paths["approval_policy"],
                        "--events",
                        paths["events"],
                    ]
                )
            self.assertEqual(validate_code, 0)
            self.assertTrue(json.loads(validate_stdout.getvalue())["ok"])

            self.assertEqual(
                main(
                    [
                        "scan",
                        "--agents",
                        paths["agents"],
                        "--mcp",
                        paths["mcp"],
                        "--identity",
                        paths["identity"],
                        "--data-catalog",
                        paths["data_catalog"],
                        "--approval-policy",
                        paths["approval_policy"],
                        "--events",
                        paths["events"],
                        "--out",
                        str(risk_json),
                        "--markdown",
                        str(risk_md),
                        "--html",
                        str(risk_html),
                    ]
                ),
                0,
            )
            self.assertTrue(risk_json.exists())
            self.assertTrue(risk_md.exists())
            self.assertTrue(risk_html.exists())

            report = json.loads(risk_json.read_text(encoding="utf-8"))
            self.assertGreaterEqual(report["summary"]["urgent"] + report["summary"]["high"], 1)
            self.assertTrue(report["attack_paths"][0]["id"].startswith("path-"))
            self.assertTrue(report["findings"][0]["id"].startswith("finding-"))
            self.assertIn(report["findings"][0]["observation_status"], {"possible_static", "observed_allowed", "observed_blocked"})

            html = risk_html.read_text(encoding="utf-8")
            self.assertIn('id="report-graph"', html)
            self.assertNotIn("https://", html)
            self.assertNotIn("http://", html)

            path_id = report["attack_paths"][0]["id"]
            explain_stdout = io.StringIO()
            with contextlib.redirect_stdout(explain_stdout):
                explain_code = main(["explain", "--findings", str(risk_json), "--path-id", path_id])
            self.assertEqual(explain_code, 0)
            self.assertIn(path_id, explain_stdout.getvalue())
            self.assertIn("observation_status=", explain_stdout.getvalue())
            self.assertIn("recommendations:", explain_stdout.getvalue())

            self.assertEqual(
                main(
                    [
                        "inventory",
                        "--agents",
                        paths["agents"],
                        "--mcp",
                        paths["mcp"],
                        "--identity",
                        paths["identity"],
                        "--data-catalog",
                        paths["data_catalog"],
                        "--approval-policy",
                        paths["approval_policy"],
                        "--out",
                        str(inventory_json),
                    ]
                ),
                0,
            )
            inventory = json.loads(inventory_json.read_text(encoding="utf-8"))
            self.assertIn("graph", inventory)
            self.assertIn("inventory", inventory)

    def test_demo_workflow_outputs_expected_files(self):
        old_cwd = Path.cwd()
        try:
            os.chdir(ROOT)
            self.assertEqual(main(["demo"]), 0)
            for relative in [
                "outputs/demo/agent-risk.json",
                "outputs/demo/agent-risk.md",
                "outputs/demo/agent-risk.html",
                "outputs/demo/inventory.json",
            ]:
                self.assertTrue((ROOT / relative).exists(), relative)
            report = json.loads((ROOT / "outputs/demo/agent-risk.json").read_text(encoding="utf-8"))
            self.assertGreaterEqual(report["summary"]["agents"], 5)
            self.assertGreaterEqual(report["summary"]["observed_allowed"], 1)
            self.assertGreaterEqual(report["summary"]["observed_blocked"], 1)
        finally:
            os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main()
