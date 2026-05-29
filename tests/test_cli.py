import contextlib
import io
import json
import os
import unittest
from argparse import Namespace
from importlib.resources import files
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import ROOT, sample_paths
from agentguard_graph.cli import cmd_collect, main


class CliTests(unittest.TestCase):
    def test_version_flag_reports_stable_release(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as raised:
                main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("agentguard-graph 1.0.0", stdout.getvalue())

    def test_sample_packs_are_package_data(self):
        sample_pack = files("agentguard_graph").joinpath("sample_packs", "support-agent")
        self.assertTrue(sample_pack.is_dir())
        self.assertIn("agentguard.json", {item.name for item in sample_pack.iterdir()})
        demo_pack = files("agentguard_graph").joinpath("sample_packs", "demo-enterprise")
        self.assertTrue(demo_pack.is_dir())
        self.assertIn("agentguard.json", {item.name for item in demo_pack.iterdir()})

    def test_scan_and_explain_commands(self):
        paths = sample_paths("support-agent")
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "risk.json"
            md = Path(tmp) / "risk.md"
            html = Path(tmp) / "risk.html"
            scan_stdout = io.StringIO()
            with contextlib.redirect_stdout(scan_stdout):
                code = main(
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
                        str(out),
                        "--markdown",
                        str(md),
                        "--html",
                        str(html),
                    ]
                )
            self.assertEqual(code, 0)
            self.assertIn("generic_tools=", scan_stdout.getvalue())
            self.assertIn("tools_missing_controls=", scan_stdout.getvalue())
            self.assertIn("prompt_boundary_risks=", scan_stdout.getvalue())
            self.assertIn("policy_rule_risks=", scan_stdout.getvalue())
            self.assertTrue(out.exists())
            self.assertTrue(md.exists())
            self.assertTrue(html.exists())
            simple_md = Path(tmp) / "simple.md"
            simple_html = Path(tmp) / "simple.html"
            simple_stdout = io.StringIO()
            with contextlib.redirect_stdout(simple_stdout):
                simple_code = main(
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
                        str(Path(tmp) / "simple.json"),
                        "--markdown",
                        str(simple_md),
                        "--html",
                        str(simple_html),
                        "--simple",
                    ]
                )
            self.assertEqual(simple_code, 0)
            self.assertIn("(simple)", simple_stdout.getvalue())
            self.assertIn("AgentGuard Graph Simple Report", simple_md.read_text(encoding="utf-8"))
            self.assertIn("simple-mode", simple_html.read_text(encoding="utf-8"))
            report = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(report["evidence_manifest"]["status"], "not_provided")
            path_id = report["attack_paths"][0]["id"]
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                explain_code = main(["explain", "--findings", str(out), "--path-id", path_id])
            self.assertEqual(explain_code, 0)
            self.assertIn(path_id, stdout.getvalue())
            self.assertIn("observation_status=", stdout.getvalue())

    def test_scan_evidence_dir_without_manifest_reports_missing_manifest(self):
        sample_dir = Path(sample_paths("support-agent")["agents"]).parent
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "risk.json"
            self.assertEqual(main(["scan", "--evidence-dir", str(sample_dir), "--out", str(out)]), 0)
            report = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(report["evidence_manifest"]["status"], "missing")
            self.assertEqual(report["evidence_manifest"]["summary"]["checked_count"], 0)

    def test_inventory_validate_and_init_commands(self):
        paths = sample_paths("support-agent")
        with TemporaryDirectory() as tmp:
            inventory = Path(tmp) / "inventory.json"
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
                        str(inventory),
                    ]
                ),
                0,
            )
            self.assertIn("inventory", json.loads(inventory.read_text(encoding="utf-8")))
            self.assertEqual(
                main(
                    [
                        "validate",
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
                    ]
                ),
                0,
            )
            json_stdout = io.StringIO()
            with contextlib.redirect_stdout(json_stdout):
                json_code = main(
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
                    ]
                )
            self.assertEqual(json_code, 0)
            self.assertTrue(json.loads(json_stdout.getvalue())["ok"])
            starter = Path(tmp) / "starter"
            self.assertEqual(main(["init", "--out", str(starter)]), 0)
            self.assertTrue((starter / "agentguard.json").exists())

            sample_starter = Path(tmp) / "sample-starter"
            self.assertEqual(main(["init", "--out", str(sample_starter), "--sample", "coding-agent"]), 0)
            self.assertTrue((sample_starter / "mcp-servers.json").exists())
            self.assertIn("coding-agent", (sample_starter / "agentguard.json").read_text(encoding="utf-8"))

            demo_starter = Path(tmp) / "demo-starter"
            self.assertEqual(main(["init", "--out", str(demo_starter), "--sample", "demo-enterprise"]), 0)
            self.assertIn("release-orchestrator-agent", (demo_starter / "agentguard.json").read_text(encoding="utf-8"))

            old_cwd = Path.cwd()
            try:
                os.chdir(tmp)
                portable_sample = Path(tmp) / "portable-sample"
                self.assertEqual(main(["init", "--out", str(portable_sample), "--sample", "support-agent"]), 0)
                self.assertIn(
                    "support-triage-agent",
                    (portable_sample / "agentguard.json").read_text(encoding="utf-8"),
                )
            finally:
                os.chdir(old_cwd)

    def test_collect_command_generates_pack_from_local_configs(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            mcp_config = tmp_path / "mcp-config.json"
            mcp_config.write_text(
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
                                "tools": ["github.create_pr"],
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            openapi = tmp_path / "openapi.json"
            openapi.write_text(
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
            output = tmp_path / "agent-evidence"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    main(
                        [
                            "collect",
                            "--out",
                            str(output),
                            "--agent-id",
                            "collected-agent",
                            "--runtime",
                            "claude-code-like",
                            "--environment",
                            "local",
                            "--autonomy",
                            "approval_required",
                            "--input-source",
                            "pull_request_comment:untrusted:External PR comments",
                            "--identity",
                            "github:code-agent",
                            "--mcp-config",
                            str(mcp_config),
                            "--openapi",
                            str(openapi),
                        ]
                    ),
                    0,
                )
            self.assertIn("collected evidence pack", stdout.getvalue())
            self.assertIn("evidence summary:", stdout.getvalue())
            agentguard = json.loads((output / "agentguard.json").read_text(encoding="utf-8"))
            tools = set(agentguard["agents"][0]["tools"])
            self.assertIn("shell.run", tools)
            self.assertIn("github.create_pr", tools)
            self.assertIn("sendCustomerMessage", tools)
            self.assertTrue((output / "openapi" / "openapi.json").exists())
            self.assertTrue((output / "collector-summary.json").exists())
            manifest = json.loads((output / "evidence-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], "0.1")
            self.assertEqual(manifest["tool"]["name"], "agentguard-graph")
            self.assertEqual(manifest["tool"]["version"], "1.0.0")
            self.assertEqual(manifest["root"], str(output.resolve()))
            manifest_paths = {entry["path"]: entry for entry in manifest["files"]}
            self.assertIn("agentguard.json", manifest_paths)
            self.assertIn("collector-summary.json", manifest_paths)
            self.assertIn("openapi/openapi.json", manifest_paths)
            self.assertEqual(manifest_paths["agentguard.json"]["source_kind"], "agent_inventory")
            self.assertEqual(manifest_paths["agentguard.json"]["schema_version"], "0.1")
            self.assertEqual(manifest_paths["openapi/openapi.json"]["source_kind"], "openapi")
            self.assertEqual(
                manifest_paths["openapi/openapi.json"]["size_bytes"],
                (output / "openapi" / "openapi.json").stat().st_size,
            )
            self.assertRegex(manifest_paths["openapi/openapi.json"]["sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn("content", manifest_paths["agentguard.json"])

            validate_stdout = io.StringIO()
            with contextlib.redirect_stdout(validate_stdout):
                self.assertEqual(
                    main(
                        [
                            "validate",
                            "--json",
                            "--evidence-dir",
                            str(output),
                        ]
                    ),
                    0,
                )
            self.assertTrue(json.loads(validate_stdout.getvalue())["ok"])

            risk_json = tmp_path / "risk.json"
            self.assertEqual(
                main(
                    [
                        "scan",
                        "--evidence-dir",
                        str(output),
                        "--out",
                        str(risk_json),
                    ]
                ),
                0,
            )
            self.assertTrue(risk_json.exists())
            report = json.loads(risk_json.read_text(encoding="utf-8"))
            self.assertEqual(report["evidence_manifest"]["status"], "present")
            self.assertEqual(report["evidence_manifest"]["path"], str(output / "evidence-manifest.json"))
            self.assertGreaterEqual(report["evidence_manifest"]["summary"]["checked_count"], 1)
            self.assertEqual(report["evidence_manifest"]["summary"]["changed_count"], 0)

            agentguard["agents"][0]["name"] = "Changed collected agent"
            (output / "agentguard.json").write_text(json.dumps(agentguard), encoding="utf-8")
            changed_risk_json = tmp_path / "risk-changed.json"
            self.assertEqual(
                main(
                    [
                        "scan",
                        "--evidence-dir",
                        str(output),
                        "--out",
                        str(changed_risk_json),
                    ]
                ),
                0,
            )
            changed_report = json.loads(changed_risk_json.read_text(encoding="utf-8"))
            changed_manifest = changed_report["evidence_manifest"]
            self.assertEqual(changed_manifest["status"], "present")
            self.assertEqual(changed_manifest["summary"]["changed_count"], 1)
            self.assertEqual(changed_manifest["changed"][0]["path"], "agentguard.json")
            self.assertIn("sha256", changed_manifest["changed"][0]["fields"])

    def test_collect_auto_discovers_project_configs(self):
        with TemporaryDirectory() as tmp:
            project = Path(tmp) / "agent-project"
            project.mkdir()
            (project / ".mcp.json").write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "workspace": {
                                "command": "mcp-shell",
                                "tools": [{"name": "shell.run", "description": "Run command"}],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            (project / "langgraph.json").write_text(
                json.dumps({"graphs": {"triage_agent": "./agent.py:graph"}, "dependencies": ["."]}),
                encoding="utf-8",
            )
            (project / "openapi.json").write_text(
                json.dumps({"openapi": "3.0.0", "paths": {"/refunds": {"post": {"operationId": "createRefund"}}}}),
                encoding="utf-8",
            )
            output = Path(tmp) / "bundle"
            self.assertEqual(
                main(
                    [
                        "collect",
                        "--project-dir",
                        str(project),
                        "--out",
                        str(output),
                        "--input-source",
                        "customer_email:untrusted",
                    ]
                ),
                0,
            )
            agentguard = json.loads((output / "agentguard.json").read_text(encoding="utf-8"))
            self.assertEqual(agentguard["agents"][0]["id"], "triage_agent")
            self.assertIn("shell.run", agentguard["agents"][0]["tools"])
            self.assertIn("createRefund", agentguard["agents"][0]["tools"])
            summary = json.loads((output / "collector-summary.json").read_text(encoding="utf-8"))
            self.assertTrue(summary["discovered_inputs"]["mcp_config"])
            self.assertTrue(summary["langgraph"][0]["graphs"])

    def test_collect_surfaces_recoverable_manifest_warnings(self):
        with TemporaryDirectory() as tmp:
            project = Path(tmp) / "manifest-project"
            project.mkdir()
            (project / "tools.json").write_text(
                json.dumps({"tools": [["bad"]], "agents": ["bad-agent"], "input_sources": ["bad-input"]}),
                encoding="utf-8",
            )
            output = Path(tmp) / "bundle"

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["collect", "--project-dir", str(project), "--out", str(output)]), 0)

            text = stdout.getvalue()
            self.assertIn("evidence summary:", text)
            self.assertIn("warning:", text)
            self.assertIn("tools[0] must be an object or string", text)
            summary = json.loads((output / "collector-summary.json").read_text(encoding="utf-8"))
            self.assertTrue(any("agents[0] must be an object" in warning for warning in summary["warnings"]))

    def test_collect_surfaces_identity_export_warnings(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            github_export = tmp_path / "github-app.json"
            github_export.write_text(json.dumps({"permissions": "bad"}), encoding="utf-8")
            output = tmp_path / "bundle"

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    main(["collect", "--out", str(output), "--github-app-export", str(github_export), "--tool", "github.read"]),
                    0,
                )

            text = stdout.getvalue()
            self.assertIn("evidence summary:", text)
            self.assertIn("warning:", text)
            self.assertIn("GitHub permissions must be an object or list", text)
            self.assertIn("no GitHub App permissions found", text)
            summary = json.loads((output / "collector-summary.json").read_text(encoding="utf-8"))
            self.assertTrue(any("GitHub permissions must be an object or list" in warning for warning in summary["warnings"]))

    def test_collect_imports_runtime_exports_as_events(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            trace_export = tmp_path / "agent-traces.json"
            trace_export.write_text(
                json.dumps(
                    {
                        "spans": [
                            {
                                "id": "span-1",
                                "trace_id": "support-1001",
                                "agent": "support-agent",
                                "name": "salesforce.get_contact",
                                "timestamp": "2026-05-18T10:00:00Z",
                                "status": "success",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output = tmp_path / "bundle"

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    main(
                        [
                            "collect",
                            "--out",
                            str(output),
                            "--tool",
                            "salesforce.get_contact",
                            "--agent-trace-export",
                            str(trace_export),
                        ]
                    ),
                    0,
                )

            events = [
                json.loads(line)
                for line in (output / "events.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            summary = json.loads((output / "collector-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(events[0]["source_kind"], "agent_trace")
            self.assertEqual(events[0]["tool"], "salesforce.get_contact")
            self.assertEqual(summary["runtime_event_imports"][0]["events"], 1)
            self.assertIn("runtime_events=1", stdout.getvalue())

    def test_collect_imports_data_classification_exports(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            dlp_export = tmp_path / "dlp-findings.json"
            dlp_export.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "resourceName": "salesforce.Contact",
                                "field": "Email",
                                "infoType": "EMAIL_ADDRESS",
                                "likelihood": "VERY_LIKELY",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output = tmp_path / "bundle"

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    main(
                        [
                            "collect",
                            "--out",
                            str(output),
                            "--tool",
                            "salesforce.get_contact",
                            "--dlp-export",
                            str(dlp_export),
                        ]
                    ),
                    0,
                )

            data_catalog = json.loads((output / "data-catalog.json").read_text(encoding="utf-8"))
            summary = json.loads((output / "collector-summary.json").read_text(encoding="utf-8"))
            imported = data_catalog["data_sources"][0]
            self.assertEqual(imported["id"], "salesforce.Contact.Email")
            self.assertIn("customer_pii", imported["data_classes"])
            self.assertEqual(summary["data_classification_imports"][0]["data_sources"], 1)
            self.assertIn("data_sources=1", stdout.getvalue())

    def test_collect_imports_policy_evaluation_exports(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            opa_export = tmp_path / "opa-decision-log.json"
            opa_export.write_text(
                json.dumps(
                    {
                        "decision_id": "dec-1",
                        "path": "agentguard/approval_required",
                        "input": {
                            "agent": "support-agent",
                            "tool": "outlook.send_email",
                            "target_system": "microsoft_365",
                            "data_classes": ["customer_pii"],
                        },
                        "result": {"approval_required": True},
                    }
                ),
                encoding="utf-8",
            )
            output = tmp_path / "bundle"

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    main(
                        [
                            "collect",
                            "--out",
                            str(output),
                            "--tool",
                            "outlook.send_email",
                            "--opa-eval",
                            str(opa_export),
                        ]
                    ),
                    0,
                )

            approval_policy = json.loads((output / "approval-policy.json").read_text(encoding="utf-8"))
            summary = json.loads((output / "collector-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(approval_policy["policies"][0]["engine"], "opa_rego")
            self.assertEqual(approval_policy["policies"][0]["rules"][0]["decision"], "approval_required")
            self.assertEqual(approval_policy["policy_evaluations"][0]["engine"], "opa_rego")
            self.assertEqual(summary["policy_evaluation_imports"][0]["policy_evaluations"], 1)
            self.assertIn("policy_evaluations=1", stdout.getvalue())

            validate_stdout = io.StringIO()
            with contextlib.redirect_stdout(validate_stdout):
                self.assertEqual(main(["validate", "--json", "--evidence-dir", str(output)]), 0)
            self.assertTrue(json.loads(validate_stdout.getvalue())["ok"])

    def test_collect_internal_entrypoint_defaults_optional_flags(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "bundle"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(cmd_collect(Namespace(out=str(output))), 0)

            agentguard = json.loads((output / "agentguard.json").read_text(encoding="utf-8"))
            summary = json.loads((output / "collector-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(agentguard["agents"][0]["id"], "collected-agent")
            self.assertTrue(any("No tool descriptors were collected" in warning for warning in summary["warnings"]))

    def test_collect_accepts_additional_enterprise_permission_exports(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            azure_export = tmp_path / "azure-rbac.json"
            azure_export.write_text(
                json.dumps(
                    {
                        "principal_id": "release-agent",
                        "roleAssignments": [
                            {
                                "scope": "/subscriptions/prod/resourceGroups/payments",
                                "roleDefinitionName": "Contributor",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = tmp_path / "bundle"

            self.assertEqual(
                main(
                    [
                        "collect",
                        "--out",
                        str(output),
                        "--tool",
                        "azure.deploy",
                        "--azure-rbac",
                        str(azure_export),
                    ]
                ),
                0,
            )

            identity = json.loads((output / "identity.json").read_text(encoding="utf-8"))
            imported = {item["id"]: item for item in identity["identities"]}
            self.assertIn("azure:release-agent", imported)
            self.assertEqual(imported["azure:release-agent"]["target_system"], "azure")
            self.assertIn("write", imported["azure:release-agent"]["permissions"][0]["actions"])

    def test_collect_writes_tool_identity_bindings(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "bundle"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    main(
                        [
                            "collect",
                            "--out",
                            str(output),
                            "--agent-id",
                            "bound-agent",
                            "--tool-identity-binding",
                            "github.create_pr=github:code-agent",
                        ]
                    ),
                    0,
                )

            agentguard = json.loads((output / "agentguard.json").read_text(encoding="utf-8"))
            identity = json.loads((output / "identity.json").read_text(encoding="utf-8"))
            summary = json.loads((output / "collector-summary.json").read_text(encoding="utf-8"))
            agent = agentguard["agents"][0]
            self.assertIn("github.create_pr", agent["tools"])
            self.assertIn("github:code-agent", agent["identities"])
            self.assertEqual(
                agent["tool_identity_bindings"],
                [{"agent": "bound-agent", "tool": "github.create_pr", "identity": "github:code-agent"}],
            )
            self.assertEqual(identity["identities"][0]["target_system"], "github")
            self.assertEqual(summary["tool_identity_bindings"], agent["tool_identity_bindings"])
            self.assertIn("bindings=1", stdout.getvalue())

            validate_stdout = io.StringIO()
            with contextlib.redirect_stdout(validate_stdout):
                self.assertEqual(main(["validate", "--json", "--evidence-dir", str(output)]), 0)
            self.assertTrue(json.loads(validate_stdout.getvalue())["ok"])

    def test_collect_auto_discovers_framework_code(self):
        with TemporaryDirectory() as tmp:
            project = Path(tmp) / "framework-project"
            project.mkdir()
            (project / "pyproject.toml").write_text(
                """
[project]
dependencies = ["openai-agents", "pydantic-ai"]
""",
                encoding="utf-8",
            )
            (project / "agents.py").write_text(
                """
from agents import Agent
from pydantic_ai import Agent as PydanticAgent

refunds = Agent(name="Refund Agent", tools=[refund_customer, send_customer_email])
weather = PydanticAgent("openai:gpt-5", tools=[weather_tool])
""",
                encoding="utf-8",
            )
            output = Path(tmp) / "bundle"

            self.assertEqual(main(["collect", "--project-dir", str(project), "--out", str(output)]), 0)

            agentguard = json.loads((output / "agentguard.json").read_text(encoding="utf-8"))
            mcp = json.loads((output / "mcp-servers.json").read_text(encoding="utf-8"))
            summary = json.loads((output / "collector-summary.json").read_text(encoding="utf-8"))

            self.assertEqual(agentguard["agents"][0]["id"], "framework-project")
            self.assertIn("refund_customer", agentguard["agents"][0]["tools"])
            self.assertIn("send_customer_email", agentguard["agents"][0]["tools"])
            self.assertIn("agent_user_prompt", agentguard["agents"][0]["input_sources"])
            self.assertTrue(any(server["transport"] == "framework_static" for server in mcp["servers"]))
            self.assertTrue(summary["discovered_inputs"]["framework_code"])
            self.assertTrue(summary["framework_code"][0]["frameworks"])

            validate_stdout = io.StringIO()
            with contextlib.redirect_stdout(validate_stdout):
                self.assertEqual(main(["validate", "--json", "--evidence-dir", str(output)]), 0)
            self.assertTrue(json.loads(validate_stdout.getvalue())["ok"])

    def test_collect_accepts_microsoft_copilot_agent_package(self):
        with TemporaryDirectory() as tmp:
            project = Path(tmp) / "copilot-project"
            app_package = project / "appPackage"
            app_package.mkdir(parents=True)
            (app_package / "manifest.json").write_text(
                json.dumps(
                    {
                        "manifestVersion": "1.24",
                        "id": "00000000-0000-0000-0000-000000000002",
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
                        "instructions": "Review finance tickets and use approved actions.",
                        "capabilities": [{"name": "Email"}],
                        "actions": [
                            {
                                "schema_version": "v2.4",
                                "name_for_human": "Finance API",
                                "description_for_model": "Create refunds and send customer emails.",
                                "functions": [
                                    {"name": "createRefund", "description": "Create payment refund"},
                                    {"name": "sendCustomerEmail", "description": "Send customer email"},
                                ],
                                "runtimes": [{"type": "OpenApi", "auth": {"type": "OAuthPluginVault"}}],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = Path(tmp) / "bundle"

            self.assertEqual(main(["collect", "--project-dir", str(project), "--out", str(output)]), 0)

            agentguard = json.loads((output / "agentguard.json").read_text(encoding="utf-8"))
            mcp = json.loads((output / "mcp-servers.json").read_text(encoding="utf-8"))
            identity = json.loads((output / "identity.json").read_text(encoding="utf-8"))
            data_catalog = json.loads((output / "data-catalog.json").read_text(encoding="utf-8"))

            self.assertEqual(agentguard["agents"][0]["id"], "finance-agent")
            self.assertEqual(agentguard["agents"][0]["runtime"], "microsoft-365-copilot")
            self.assertIn("sendCustomerEmail", agentguard["agents"][0]["tools"])
            self.assertIn("microsoft_365_copilot_user_prompt", agentguard["agents"][0]["input_sources"])
            self.assertTrue(any(server["transport"] == "copilot_plugin" for server in mcp["servers"]))
            self.assertIn("microsoft365:user-delegated", {item["id"] for item in identity["identities"]})
            self.assertIn("microsoft365.email", {item["id"] for item in data_catalog["data_sources"]})

            validate_stdout = io.StringIO()
            with contextlib.redirect_stdout(validate_stdout):
                self.assertEqual(main(["validate", "--json", "--evidence-dir", str(output)]), 0)
            self.assertTrue(json.loads(validate_stdout.getvalue())["ok"])

            risk_json = Path(tmp) / "copilot-risk.json"
            self.assertEqual(main(["scan", "--evidence-dir", str(output), "--out", str(risk_json)]), 0)
            report = json.loads(risk_json.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["agents"], 1)
            self.assertTrue(any("createRefund" in finding["title"] for finding in report["findings"]))

    def test_demo_command_writes_outputs(self):
        old_cwd = Path.cwd()
        try:
            os.chdir(ROOT)
            self.assertEqual(main(["demo"]), 0)
            self.assertTrue((ROOT / "outputs" / "demo" / "agent-risk.json").exists())
            self.assertTrue((ROOT / "outputs" / "demo" / "inventory.json").exists())
            report = json.loads((ROOT / "outputs" / "demo" / "agent-risk.json").read_text(encoding="utf-8"))
            self.assertGreaterEqual(report["summary"]["agents"], 6)
            self.assertGreaterEqual(report["summary"]["observed_blocked"], 1)
            self.assertTrue(
                any(agent["runtime"] == "microsoft-365-copilot" for agent in report["inventory"]["agents"])
            )
            self.assertEqual(main(["demo", "--simple"]), 0)
            self.assertIn(
                "AgentGuard Graph Simple Report",
                (ROOT / "outputs" / "demo" / "agent-risk.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "simple-mode",
                (ROOT / "outputs" / "demo" / "agent-risk.html").read_text(encoding="utf-8"),
            )
            simple_report = json.loads((ROOT / "outputs" / "demo" / "agent-risk.json").read_text(encoding="utf-8"))
            self.assertGreaterEqual(simple_report["summary"]["agents"], 6)
        finally:
            os.chdir(old_cwd)

    def test_cli_error_paths(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bad_report = tmp_path / "bad-report.json"
            bad_report.write_text("{bad", encoding="utf-8")

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main(["explain", "--findings", str(bad_report), "--path-id", "path-missing"]), 2)
            self.assertIn("cannot read findings report", stderr.getvalue())

            empty_report = tmp_path / "empty-report.json"
            empty_report.write_text('{"attack_paths": [], "findings": []}', encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main(["explain", "--findings", str(empty_report), "--path-id", "path-missing"]), 2)
            self.assertIn("path not found", stderr.getvalue())

            array_report = tmp_path / "array-report.json"
            array_report.write_text("[]", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main(["explain", "--findings", str(array_report), "--path-id", "path-missing"]), 2)
            self.assertIn("must be a JSON object", stderr.getvalue())

            malformed_sections = tmp_path / "bad-sections-report.json"
            malformed_sections.write_text('{"attack_paths": {}, "findings": []}', encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main(["explain", "--findings", str(malformed_sections), "--path-id", "path-missing"]), 2)
            self.assertIn("attack_paths must be a list", stderr.getvalue())

            report_with_paths = tmp_path / "report-with-paths.json"
            report_with_paths.write_text(
                json.dumps({"attack_paths": [{"id": "path-known", "title": "Known path"}], "findings": []}),
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main(["explain", "--findings", str(report_with_paths), "--path-id", "path-missing"]), 2)
            self.assertIn("available path ids: path-known", stderr.getvalue())

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(
                    main(
                        [
                            "scan",
                            "--agents",
                            str(tmp_path / "missing-agentguard.json"),
                            "--out",
                            str(tmp_path / "out.json"),
                        ]
                    ),
                    2,
                )
            self.assertIn("file not found", stderr.getvalue())

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(
                    main(
                        [
                            "validate",
                            "--evidence-dir",
                            str(tmp_path / "missing-evidence-pack"),
                        ]
                    ),
                    2,
                )
            self.assertIn("evidence directory not found", stderr.getvalue())

            output_file = tmp_path / "not-a-directory"
            output_file.write_text("", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main(["collect", "--out", str(output_file)]), 2)
            self.assertIn("exists but is not a directory", stderr.getvalue())

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(
                    main(["collect", "--out", str(tmp_path / "bad-input"), "--input-source", "customer:internet"]),
                    2,
                )
            self.assertIn("invalid trust value", stderr.getvalue())

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(
                    main(["collect", "--out", str(tmp_path / "bad-identity"), "--identity", "github:app="]),
                    2,
                )
            self.assertIn("id=type:target_system", stderr.getvalue())

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(
                    main(["collect", "--out", str(tmp_path / "bad-binding"), "--tool-identity-binding", "github.create_pr"]),
                    2,
                )
            self.assertIn("TOOL=IDENTITY", stderr.getvalue())

            out_dir = tmp_path / "scan-output-dir"
            out_dir.mkdir()
            paths = sample_paths("support-agent")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
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
                            str(out_dir),
                        ]
                    ),
                    2,
                )
            self.assertIn("cannot write JSON report", stderr.getvalue())

    def test_scan_and_inventory_return_validation_errors(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bad_agents = tmp_path / "agentguard.json"
            bad_agents.write_text('{"schema_version":"0.1","agents":[{"id":"a"}]}', encoding="utf-8")
            scan_stdout = io.StringIO()
            with contextlib.redirect_stdout(scan_stdout):
                self.assertEqual(main(["scan", "--agents", str(bad_agents), "--out", str(tmp_path / "risk.json")]), 2)
            self.assertIn("validation: failed", scan_stdout.getvalue())
            self.assertIn("missing required field", scan_stdout.getvalue())

            inventory_stdout = io.StringIO()
            with contextlib.redirect_stdout(inventory_stdout):
                self.assertEqual(
                    main(["inventory", "--agents", str(bad_agents), "--out", str(tmp_path / "inventory.json")]),
                    2,
                )
            self.assertIn("validation: failed", inventory_stdout.getvalue())
            self.assertIn("missing required field", inventory_stdout.getvalue())

    def test_scan_and_inventory_require_agent_evidence(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            empty_pack = tmp_path / "empty-pack"
            empty_pack.mkdir()

            scan_out = tmp_path / "empty-risk.json"
            scan_stdout = io.StringIO()
            with contextlib.redirect_stdout(scan_stdout):
                self.assertEqual(main(["scan", "--evidence-dir", str(empty_pack), "--out", str(scan_out)]), 2)
            self.assertIn("scan requires agent evidence", scan_stdout.getvalue())
            self.assertFalse(scan_out.exists())

            empty_agents = tmp_path / "agentguard.json"
            empty_agents.write_text('{"schema_version":"0.1","agents":[]}', encoding="utf-8")
            inventory_out = tmp_path / "empty-inventory.json"
            inventory_stdout = io.StringIO()
            with contextlib.redirect_stdout(inventory_stdout):
                self.assertEqual(main(["inventory", "--agents", str(empty_agents), "--out", str(inventory_out)]), 2)
            self.assertIn("inventory requires at least one agent", inventory_stdout.getvalue())
            self.assertFalse(inventory_out.exists())

    def test_validate_text_output_labels_info_clearly(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(main(["validate"]), 0)

        output = stdout.getvalue()
        self.assertIn("validation: ok (0 errors, 0 warnings,", output)
        self.assertIn(" info)", output)
        self.assertIn("info: no agent evidence provided", output)
        self.assertNotIn("inf:", output)


if __name__ == "__main__":
    unittest.main()
