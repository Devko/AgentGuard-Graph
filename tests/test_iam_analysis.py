import unittest

from _helpers import build_report, load_report


class IAMAnalysisTests(unittest.TestCase):
    def test_binding_coverage_reports_explicit_inferred_ambiguous_and_unused_grants(self):
        evidence = {
            "agents": {
                "agents": [
                    {
                        "id": "multi-identity-agent",
                        "owner": "platform",
                        "runtime": "custom",
                        "environment": "production",
                        "autonomy": "approval_required",
                        "input_sources": ["ticket"],
                        "tools": [
                            "github.contents_read",
                            "github.pull_requests_create",
                            "slack.chat_post_message",
                        ],
                        "identities": [
                            "github:reader",
                            "github:writer",
                            "slack:bot",
                            "okta:admin",
                        ],
                        "tool_identity_bindings": [
                            {
                                "agent": "multi-identity-agent",
                                "tool": "github.pull_requests_create",
                                "identity": "github:writer",
                            }
                        ],
                        "memory": [],
                        "approval_policy": "agent-policy",
                    }
                ],
                "input_sources": [{"id": "ticket", "trust": "untrusted", "description": "Support ticket"}],
                "memory_stores": [],
            },
            "mcp": {
                "servers": [],
                "tools": [
                    {
                        "id": "github.contents_read",
                        "name": "github.contents_read",
                        "target_system": "github",
                        "risk_tags": ["read_action"],
                        "risk_confidence": "high",
                    },
                    {
                        "id": "github.pull_requests_create",
                        "name": "github.pull_requests_create",
                        "target_system": "github",
                        "risk_tags": ["repository_write"],
                        "risk_confidence": "high",
                    },
                    {
                        "id": "slack.chat_post_message",
                        "name": "slack.chat_post_message",
                        "target_system": "slack",
                        "risk_tags": ["external_message"],
                        "risk_confidence": "high",
                    },
                ],
            },
            "openapi": {"tools": []},
            "identity": {
                "identities": [
                    {
                        "id": "github:reader",
                        "type": "github_app",
                        "target_system": "github",
                        "permissions": [
                            {"resource": "contents", "actions": ["read"], "data_classes": ["source_code"]}
                        ],
                    },
                    {
                        "id": "github:writer",
                        "type": "github_app",
                        "target_system": "github",
                        "permissions": [
                            {"resource": "pull_requests", "actions": ["write"], "data_classes": ["source_code"]},
                            {"resource": "secrets", "actions": ["write"], "data_classes": ["secrets"]},
                        ],
                    },
                    {
                        "id": "slack:bot",
                        "type": "oauth_client",
                        "target_system": "slack",
                        "permissions": [
                            {"resource": "chat", "actions": ["write"], "data_classes": ["customer_pii"]}
                        ],
                    },
                    {
                        "id": "okta:admin",
                        "type": "oauth_client",
                        "target_system": "okta",
                        "permissions": [
                            {"resource": "users", "actions": ["admin"], "data_classes": ["employee_pii"]}
                        ],
                    },
                ]
            },
            "data_catalog": {"data_sources": []},
            "approval_policy": {
                "policies": [
                    {
                        "id": "agent-policy",
                        "rules": [
                            {
                                "id": "external-message-approval",
                                "match": {"risk_tag": ["external_message"]},
                                "decision": "approval_required",
                                "controls": ["audit_logging"],
                            }
                        ],
                    }
                ]
            },
            "events": {"events": []},
        }

        report = build_report(evidence)
        iam = report["iam_analysis"]
        coverage = {item["tool"]: item for item in iam["binding_coverage"]}

        self.assertEqual(coverage["github.pull_requests_create"]["binding_type"], "explicit")
        self.assertEqual(coverage["slack.chat_post_message"]["binding_type"], "inferred")
        self.assertEqual(coverage["github.contents_read"]["binding_type"], "ambiguous")
        self.assertEqual(
            set(coverage["github.contents_read"]["ambiguous_same_target_identities"]),
            {"github:reader", "github:writer"},
        )
        self.assertEqual(iam["summary"]["explicit_bindings"], 1)
        self.assertEqual(iam["summary"]["inferred_bindings"], 1)
        self.assertEqual(iam["summary"]["ambiguous_bindings"], 1)
        self.assertTrue(any(item["identity"] == "okta:admin" for item in iam["unused_identities"]))
        self.assertTrue(
            any(item["identity"] == "github:writer" and item["resource"] == "secrets" for item in iam["unused_permissions"])
        )
        self.assertTrue(any(item["target_system"] == "github" and item["priority"] == "P0" for item in iam["least_privilege_suggestions"]))
        self.assertEqual(report["summary"]["ambiguous_bindings"], 1)

    def test_report_contract_includes_iam_analysis_for_samples(self):
        report = load_report("support-agent")

        self.assertIn("iam_analysis", report)
        self.assertIn("binding_coverage", report["iam_analysis"])
        self.assertIn("least_privilege_suggestions", report["iam_analysis"])


if __name__ == "__main__":
    unittest.main()
