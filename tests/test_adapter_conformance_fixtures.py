import contextlib
import io
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import ROOT
from agentguard_graph.adapters.identity_exports import (
    parse_aws_iam_policy_export,
    parse_github_app_export,
    parse_kubernetes_rbac_export,
    parse_oauth_scope_export,
    parse_salesforce_permissions_export,
)
from agentguard_graph.adapters.openclaw_config import parse_openclaw_config
from agentguard_graph.adapters.tool_manifest import parse_tool_manifest
from agentguard_graph.cli import main


FIXTURES = ROOT / "tests" / "fixtures" / "adapters"


class AdapterConformanceFixtureTests(unittest.TestCase):
    def test_openclaw_fixture_normalizes_agent_tools_and_channels(self):
        parsed = parse_openclaw_config(FIXTURES / "openclaw_enterprise.json")

        self.assertEqual(parsed["warnings"], [])
        agent = parsed["agents"][0]
        self.assertEqual(agent["id"], "ops-remediation-agent")
        self.assertEqual(agent["environment"], "production")
        self.assertIn("openclaw.exec", agent["tools"])
        self.assertIn("openclaw.fs", agent["tools"])
        self.assertIn("openclaw.github", agent["tools"])
        self.assertIn("incident_slack_channel", agent["input_sources"])
        self.assertEqual([source["id"] for source in parsed["input_sources"]], ["incident_slack_channel"])

    def test_langchain_custom_manifest_fixture_normalizes_tools_agents_and_inputs(self):
        parsed = parse_tool_manifest(FIXTURES / "langchain_custom_manifest.json")

        self.assertEqual(parsed["warnings"], ["langchain_custom_manifest.json: tools[0] ignored unknown risk_tags: not_a_real_tag"])
        tools = {tool["name"]: tool for tool in parsed["tools"]}
        self.assertEqual(tools["github.create_pr"]["risk_tags"], ["repository_write"])
        self.assertEqual(tools["salesforce.get_contact"]["target_system"], "salesforce")
        self.assertEqual(tools["slack.post_message"]["target_system"], "slack")
        self.assertIn("input_schema", tools["github.create_pr"])
        self.assertEqual(parsed["agents"][0]["identities"], ["github:ops-review-app", "slack:ops-bot", "salesforce:support-profile"])
        self.assertEqual(parsed["input_sources"][0]["trust"], "untrusted")

    def test_github_app_fixture_accepts_manifest_default_permissions(self):
        parsed = parse_github_app_export(FIXTURES / "github_app_manifest.json")
        identity = parsed["identities"][0]

        self.assertEqual(parsed["warnings"], [])
        self.assertEqual(identity["id"], "github:ops-review-app")
        permissions = {permission["resource"]: permission for permission in identity["permissions"]}
        self.assertEqual(permissions["github.contents"]["actions"], ["read", "write"])
        self.assertEqual(permissions["github.metadata"]["actions"], ["read"])
        classes = {klass for permission in permissions.values() for klass in permission["data_classes"]}
        self.assertIn("source_code", classes)
        self.assertIn("secrets", classes)
        self.assertIn("production_config", classes)

    def test_oauth_fixtures_accept_slack_manifest_and_google_scope_string(self):
        slack = parse_oauth_scope_export(FIXTURES / "slack_oauth_manifest.json")["identities"][0]
        google = parse_oauth_scope_export(FIXTURES / "google_oauth_tokeninfo.json")["identities"][0]

        self.assertEqual(slack["target_system"], "slack")
        self.assertEqual(slack["scopes"], ["chat:write", "channels:read", "files:read", "users:read"])
        self.assertIn("write", slack["permissions"][0]["actions"])
        self.assertEqual(google["target_system"], "google_workspace")
        self.assertEqual(
            google["scopes"],
            [
                "https://www.googleapis.com/auth/gmail.readonly",
                "https://www.googleapis.com/auth/drive.file",
                "profile",
            ],
        )
        google_classes = {klass for permission in google["permissions"] for klass in permission["data_classes"]}
        self.assertIn("customer_pii", google_classes)
        self.assertIn("employee_pii", google_classes)

    def test_salesforce_aws_and_kubernetes_fixtures_normalize_permissions(self):
        salesforce = parse_salesforce_permissions_export(FIXTURES / "salesforce_profile_permissions.json")["identities"][0]
        aws = parse_aws_iam_policy_export(FIXTURES / "aws_policy_document.json")["identities"][0]
        kubernetes = parse_kubernetes_rbac_export(FIXTURES / "kubernetes_rbac_list.json")

        salesforce_permissions = {permission["resource"]: permission for permission in salesforce["permissions"]}
        self.assertIn("write", salesforce_permissions["salesforce.Contact"]["actions"])
        self.assertIn("financial_data", salesforce_permissions["salesforce.Payment__c"]["data_classes"])

        self.assertEqual(aws["id"], "aws:agent-runtime-role")
        aws_classes = {klass for permission in aws["permissions"] for klass in permission["data_classes"]}
        self.assertIn("secrets", aws_classes)
        self.assertIn("production_config", aws_classes)

        self.assertEqual(kubernetes["warnings"], [])
        self.assertEqual(
            {identity["id"] for identity in kubernetes["identities"]},
            {"kubernetes:agent-secret-reader", "kubernetes:namespace-log-reader"},
        )
        kubernetes_classes = {
            klass
            for identity in kubernetes["identities"]
            for permission in identity["permissions"]
            for klass in permission["data_classes"]
        }
        self.assertIn("secrets", kubernetes_classes)
        self.assertIn("production_config", kubernetes_classes)
        self.assertIn("security_logs", kubernetes_classes)

    def test_collector_accepts_conformance_fixture_corpus(self):
        with TemporaryDirectory() as tmp:
            evidence_dir = Path(tmp) / "evidence"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    main(
                        [
                            "collect",
                            "--out",
                            str(evidence_dir),
                            "--openclaw-config",
                            str(FIXTURES / "openclaw_enterprise.json"),
                            "--langchain-manifest",
                            str(FIXTURES / "langchain_custom_manifest.json"),
                            "--github-app-export",
                            str(FIXTURES / "github_app_manifest.json"),
                            "--oauth-scopes-export",
                            str(FIXTURES / "slack_oauth_manifest.json"),
                            "--oauth-scopes-export",
                            str(FIXTURES / "google_oauth_tokeninfo.json"),
                            "--salesforce-permissions-export",
                            str(FIXTURES / "salesforce_profile_permissions.json"),
                            "--aws-iam-policy",
                            str(FIXTURES / "aws_policy_document.json"),
                            "--kubernetes-rbac",
                            str(FIXTURES / "kubernetes_rbac_list.json"),
                        ]
                    ),
                    0,
                )

            agentguard = json.loads((evidence_dir / "agentguard.json").read_text(encoding="utf-8"))
            mcp = json.loads((evidence_dir / "mcp-servers.json").read_text(encoding="utf-8"))
            identity = json.loads((evidence_dir / "identity.json").read_text(encoding="utf-8"))

            self.assertEqual(agentguard["agents"][0]["id"], "ops-remediation-agent")
            self.assertIn("incident_slack_channel", agentguard["agents"][0]["input_sources"])
            agent_tools = set(agentguard["agents"][0]["tools"])
            self.assertIn("openclaw.exec", agent_tools)
            self.assertIn("github.create_pr", agent_tools)
            self.assertIn("salesforce.get_contact", agent_tools)
            self.assertIn("slack.post_message", agent_tools)
            self.assertGreaterEqual(len(mcp["servers"]), 2)
            self.assertEqual(
                {
                    "aws:agent-runtime-role",
                    "github:ops-review-app",
                    "google:workspace-agent",
                    "kubernetes:agent-secret-reader",
                    "kubernetes:namespace-log-reader",
                    "salesforce:support-profile",
                    "slack:ops-bot",
                },
                {item["id"] for item in identity["identities"]},
            )

            validate_stdout = io.StringIO()
            with contextlib.redirect_stdout(validate_stdout):
                self.assertEqual(main(["validate", "--json", "--evidence-dir", str(evidence_dir)]), 0)
            self.assertTrue(json.loads(validate_stdout.getvalue())["ok"])


if __name__ == "__main__":
    unittest.main()
