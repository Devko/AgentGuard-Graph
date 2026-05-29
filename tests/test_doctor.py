import contextlib
import io
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import _helpers  # noqa: F401 - adds src/ to sys.path for focused test runs
from agentguard_graph.cli import main
from agentguard_graph.manifest import write_evidence_manifest


class DoctorCommandTests(unittest.TestCase):
    def test_doctor_recommends_specific_exports_for_incomplete_pack(self):
        with TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "agent-evidence"
            evidence.mkdir()
            (evidence / "agentguard.json").write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "agents": [
                            {
                                "id": "support-agent",
                                "owner": "support-platform",
                                "runtime": "custom",
                                "environment": "production",
                                "autonomy": "autonomous",
                                "input_sources": ["customer_email"],
                                "tools": ["salesforce.get_contact", "gmail.send_email"],
                                "identities": ["salesforce:support-agent", "google:support-agent"],
                                "memory": [],
                                "approval_policy": "support-policy",
                            }
                        ],
                        "input_sources": [
                            {
                                "id": "customer_email",
                                "trust": "untrusted",
                                "description": "Customer-controlled support email",
                            }
                        ],
                        "memory_stores": [],
                    }
                ),
                encoding="utf-8",
            )
            (evidence / "mcp-servers.json").write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "servers": [
                            {
                                "id": "support-tools",
                                "name": "Support tools",
                                "transport": "stdio",
                                "auth": "unknown",
                                "tools": [
                                    {
                                        "name": "salesforce.get_contact",
                                        "description": "Read Salesforce contacts",
                                        "target_system": "salesforce",
                                        "risk_tags": ["sensitive_read"],
                                    },
                                    {
                                        "name": "gmail.send_email",
                                        "description": "Send email externally",
                                        "target_system": "google_workspace",
                                        "risk_tags": ["external_message"],
                                    },
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (evidence / "identity.json").write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "identities": [
                            {
                                "id": "salesforce:support-agent",
                                "type": "oauth_client",
                                "target_system": "salesforce",
                                "scopes": [],
                                "permissions": [],
                            },
                            {
                                "id": "google:support-agent",
                                "type": "oauth_client",
                                "target_system": "google_workspace",
                                "scopes": [],
                                "permissions": [],
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (evidence / "data-catalog.json").write_text('{"schema_version":"0.1","data_sources":[]}', encoding="utf-8")
            (evidence / "approval-policy.json").write_text(
                '{"schema_version":"0.1","policies":[{"id":"support-policy","rules":[]}]}',
                encoding="utf-8",
            )
            (evidence / "events.jsonl").write_text("", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["doctor", "--evidence-dir", str(evidence), "--json"]), 0)
            report = json.loads(stdout.getvalue())

            self.assertEqual(report["status"], "needs_evidence")
            self.assertTrue(report["package_ready"])
            self.assertFalse(report["secret_findings"])
            exports = report["recommended_exports"]
            self.assertTrue(any(item["target"] == "salesforce" and "--salesforce-permissions-export" in item["command"] for item in exports))
            self.assertTrue(any(item["target"] == "google_workspace" and "--oauth-scopes-export" in item["command"] for item in exports))
            self.assertTrue(any(item["file"] == "data-catalog.json" for item in exports))
            self.assertTrue(any(item["file"] == "approval-policy.json" for item in exports))
            self.assertTrue(any(item["file"] == "events.jsonl" for item in exports))

    def test_doctor_blocks_packaging_when_secret_values_are_present(self):
        with TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "agent-evidence"
            evidence.mkdir()
            secret_value = "super-secret-client-value"
            (evidence / "agentguard.json").write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "agents": [
                            {
                                "id": "a",
                                "owner": "team",
                                "runtime": "custom",
                                "environment": "production",
                                "autonomy": "approval_required",
                                "input_sources": [],
                                "tools": [],
                                "identities": [],
                                "memory": [],
                                "approval_policy": "p",
                            }
                        ],
                        "input_sources": [],
                        "memory_stores": [],
                        "client_secret": secret_value,
                    }
                ),
                encoding="utf-8",
            )
            (evidence / "mcp-servers.json").write_text('{"schema_version":"0.1","servers":[]}', encoding="utf-8")
            (evidence / "identity.json").write_text('{"schema_version":"0.1","identities":[]}', encoding="utf-8")
            (evidence / "data-catalog.json").write_text('{"schema_version":"0.1","data_sources":[]}', encoding="utf-8")
            (evidence / "approval-policy.json").write_text('{"schema_version":"0.1","policies":[]}', encoding="utf-8")
            (evidence / "events.jsonl").write_text("", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["doctor", "--evidence-dir", str(evidence), "--json"])
            self.assertEqual(code, 3)
            self.assertNotIn(secret_value, stdout.getvalue())
            report = json.loads(stdout.getvalue())
            self.assertEqual(report["status"], "blocked_by_secrets")
            self.assertFalse(report["package_ready"])
            self.assertEqual(report["secret_findings"][0]["json_path"], "$.client_secret")
            self.assertIn("fingerprint", report["secret_findings"][0])

    def test_doctor_project_discovery_suggests_collect_command(self):
        with TemporaryDirectory() as tmp:
            project = Path(tmp) / "agent-project"
            project.mkdir()
            (project / ".mcp.json").write_text(
                json.dumps({"mcpServers": {"workspace": {"command": "mcp-shell", "tools": ["shell.run"]}}}),
                encoding="utf-8",
            )
            (project / "github-app-permissions.json").write_text(
                json.dumps({"identity_id": "github:code-agent", "permissions": {"contents": "write"}}),
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["doctor", "--project-dir", str(project), "--json"]), 0)
            report = json.loads(stdout.getvalue())

            self.assertEqual(report["project_discovery"]["found"]["mcp_config"], [str(project / ".mcp.json")])
            self.assertEqual(
                report["project_discovery"]["found"]["github_app_export"],
                [str(project / "github-app-permissions.json")],
            )
            self.assertTrue(any(item["kind"] == "project_collection" for item in report["recommended_exports"]))
            self.assertIn("agentguard-graph collect --project-dir", report["project_discovery"]["recommended_collect_command"])

    def test_doctor_write_plan_includes_profile_actions_and_precise_repairs(self):
        with TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "agent-evidence"
            evidence.mkdir()
            plan_path = Path(tmp) / "collection-plan.json"
            (evidence / "agentguard.json").write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "agents": [
                            {
                                "id": "support-agent",
                                "owner": "support-platform",
                                "runtime": "custom",
                                "environment": "production",
                                "autonomy": "autonomous",
                                "input_sources": ["missing_ticket"],
                                "tools": ["salesforce.get_contact", "missing.tool"],
                                "identities": ["salesforce:support-agent"],
                                "memory": ["missing_memory"],
                                "approval_policy": "missing-policy",
                            }
                        ],
                        "input_sources": [],
                        "memory_stores": [],
                    }
                ),
                encoding="utf-8",
            )
            (evidence / "mcp-servers.json").write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "servers": [
                            {
                                "id": "support-tools",
                                "transport": "stdio",
                                "auth": "unknown",
                                "tools": [
                                    {
                                        "name": "salesforce.get_contact",
                                        "description": "Read Salesforce contacts",
                                        "target_system": "salesforce",
                                        "risk_tags": ["sensitive_read"],
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (evidence / "identity.json").write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "identities": [
                            {
                                "id": "salesforce:support-agent",
                                "type": "oauth_client",
                                "target_system": "salesforce",
                                "scopes": [],
                                "permissions": [],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (evidence / "data-catalog.json").write_text('{"schema_version":"0.1","data_sources":[]}', encoding="utf-8")
            (evidence / "approval-policy.json").write_text('{"schema_version":"0.1","policies":[]}', encoding="utf-8")
            (evidence / "events.jsonl").write_text("", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    main(
                        [
                            "doctor",
                            "--evidence-dir",
                            str(evidence),
                            "--profile",
                            "developer",
                            "--write-plan",
                            str(plan_path),
                            "--json",
                        ]
                    ),
                    0,
                )
            report = json.loads(stdout.getvalue())
            plan = json.loads(plan_path.read_text(encoding="utf-8"))

            self.assertEqual(report["profile_view"]["profile"], "developer")
            self.assertEqual(plan["plan_type"], "agentguard_graph_collection_plan")
            self.assertTrue(all(action["owner"] and action["repair_text"] for action in plan["actions"]))
            repair_categories = {action["repair_category"] for action in plan["actions"]}
            self.assertIn("missing_reference", repair_categories)
            self.assertIn("weak_identity_evidence", repair_categories)
            self.assertIn("absent_data_classification", repair_categories)
            self.assertIn("missing_approval_policy", repair_categories)
            self.assertTrue(any(action["file"] == "data-catalog.json" and action["owner"] == "data owner" for action in plan["actions"]))
            self.assertTrue(any("Missing reference repair" in action["repair_text"] for action in plan["actions"]))
            self.assertTrue(any("Weak identity evidence repair" in action["repair_text"] for action in plan["actions"]))
            self.assertLess(len(report["profile_view"]["actions"]), len(plan["actions"]))

    def test_doctor_framework_checklists_detect_onboarding_sources(self):
        with TemporaryDirectory() as tmp:
            project = Path(tmp) / "agent-project"
            (project / "appPackage").mkdir(parents=True)
            (project / ".mcp.json").write_text(
                json.dumps({"mcpServers": {"workspace": {"command": "mcp-shell", "tools": ["shell.run"]}}}),
                encoding="utf-8",
            )
            (project / "langgraph.json").write_text(
                json.dumps({"graphs": {"support": "./agent.py:graph"}}),
                encoding="utf-8",
            )
            (project / "langchain-tools.json").write_text(
                json.dumps({"tools": [{"name": "crm.lookup", "target_system": "salesforce"}]}),
                encoding="utf-8",
            )
            (project / "appPackage" / "manifest.json").write_text(
                json.dumps({"name": {"short": "Ops Copilot"}, "copilotAgents": {"declarativeAgents": []}}),
                encoding="utf-8",
            )
            (project / "pyproject.toml").write_text("[project]\ndependencies = ['langchain']\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["doctor", "--project-dir", str(project), "--profile", "security-reviewer", "--json"]), 0)
            report = json.loads(stdout.getvalue())
            checklists = {item["id"]: item for item in report["framework_checklists"]}

            for checklist_id in ["copilot", "mcp", "langgraph", "langchain_custom_manifest", "static_framework_scan"]:
                self.assertEqual(checklists[checklist_id]["status"], "detected")
                self.assertTrue(checklists[checklist_id]["steps"])
                self.assertTrue(all(step["owner"] and step["reason"] and step["repair_text"] for step in checklists[checklist_id]["steps"]))
            self.assertTrue(report["profile_view"]["framework_checklists"])

    def test_doctor_text_output_includes_summary_counts(self):
        with TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "agent-evidence"
            evidence.mkdir()
            (evidence / "agentguard.json").write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "agents": [
                            {
                                "id": "a",
                                "owner": "team",
                                "runtime": "custom",
                                "environment": "production",
                                "autonomy": "approval_required",
                                "input_sources": [],
                                "tools": [],
                                "identities": [],
                                "memory": [],
                                "approval_policy": "p",
                            }
                        ],
                        "input_sources": [],
                        "memory_stores": [],
                    }
                ),
                encoding="utf-8",
            )
            (evidence / "mcp-servers.json").write_text('{"schema_version":"0.1","servers":[]}', encoding="utf-8")
            (evidence / "identity.json").write_text('{"schema_version":"0.1","identities":[]}', encoding="utf-8")
            (evidence / "data-catalog.json").write_text('{"schema_version":"0.1","data_sources":[]}', encoding="utf-8")
            (evidence / "approval-policy.json").write_text('{"schema_version":"0.1","policies":[]}', encoding="utf-8")
            (evidence / "events.jsonl").write_text("", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["doctor", "--evidence-dir", str(evidence)]), 0)

            output = stdout.getvalue()
            self.assertIn("doctor:", output)
            self.assertIn("doctor summary:", output)
            self.assertIn("evidence_files=", output)
            self.assertIn("manifest=missing", output)
            self.assertIn("recommended_exports=", output)
            self.assertIn("collection plan", output)
            self.assertIn("owner:", output)

    def test_doctor_reports_manifest_changed_missing_and_unmanifested_files(self):
        with TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "agent-evidence"
            evidence.mkdir()
            (evidence / "agentguard.json").write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "agents": [
                            {
                                "id": "a",
                                "owner": "team",
                                "runtime": "custom",
                                "environment": "production",
                                "autonomy": "approval_required",
                                "input_sources": [],
                                "tools": [],
                                "identities": [],
                                "memory": [],
                                "approval_policy": "p",
                            }
                        ],
                        "input_sources": [],
                        "memory_stores": [],
                    }
                ),
                encoding="utf-8",
            )
            (evidence / "mcp-servers.json").write_text('{"schema_version":"0.1","servers":[]}', encoding="utf-8")
            (evidence / "identity.json").write_text('{"schema_version":"0.1","identities":[]}', encoding="utf-8")
            (evidence / "approval-policy.json").write_text('{"schema_version":"0.1","policies":[]}', encoding="utf-8")
            (evidence / "events.jsonl").write_text("", encoding="utf-8")
            write_evidence_manifest(
                evidence,
                [
                    "agentguard.json",
                    "mcp-servers.json",
                    "identity.json",
                    "approval-policy.json",
                    "events.jsonl",
                ],
            )

            (evidence / "agentguard.json").write_text(
                (evidence / "agentguard.json").read_text(encoding="utf-8").replace('"owner": "team"', '"owner": "other-team"'),
                encoding="utf-8",
            )
            (evidence / "identity.json").unlink()
            (evidence / "collector-summary.json").write_text('{"schema_version":"0.1"}', encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["doctor", "--evidence-dir", str(evidence), "--json"]), 0)

            report = json.loads(stdout.getvalue())
            self.assertEqual(report["manifest"]["status"], "present")
            self.assertEqual(report["manifest"]["summary"]["changed_count"], 1)
            self.assertEqual(report["manifest"]["summary"]["missing_count"], 1)
            self.assertEqual(report["manifest"]["summary"]["unmanifested_count"], 1)
            self.assertEqual(report["summary"]["manifest_status"], "present")
            self.assertEqual(report["summary"]["manifest_changed"], 1)
            self.assertEqual(report["summary"]["manifest_missing"], 1)
            self.assertEqual(report["summary"]["manifest_unmanifested"], 1)
            self.assertEqual(report["manifest"]["changed"][0]["path"], "agentguard.json")
            self.assertEqual(report["manifest"]["missing"][0]["path"], "identity.json")
            self.assertEqual(report["manifest"]["unmanifested"][0]["path"], "collector-summary.json")


if __name__ == "__main__":
    unittest.main()
