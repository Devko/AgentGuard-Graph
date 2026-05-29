import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import _helpers
from agentguard_graph.adapters.identity_exports import (
    parse_aws_iam_policy_export,
    parse_azure_rbac_export,
    parse_confluence_permissions_export,
    parse_databricks_permissions_export,
    parse_dataverse_permissions_export,
    parse_gcp_iam_policy_export,
    parse_github_app_export,
    parse_jira_permissions_export,
    parse_kubernetes_rbac_export,
    parse_microsoft_365_permission_export,
    parse_netsuite_permissions_export,
    parse_okta_permissions_export,
    parse_oauth_scope_export,
    parse_power_platform_permissions_export,
    parse_servicenow_permissions_export,
    parse_salesforce_permissions_export,
    parse_snowflake_grants_export,
    parse_stripe_permissions_export,
    parse_zendesk_permissions_export,
)


class IdentityExportAdapterTests(unittest.TestCase):
    def test_github_app_permission_export(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "github-app.json"
            path.write_text(
                json.dumps(
                    {
                        "identity_id": "github:code-agent",
                        "permissions": {
                            "contents": "write",
                            "pull_requests": "write",
                            "metadata": "read",
                            "secrets": "read",
                        },
                    }
                ),
                encoding="utf-8",
            )
            parsed = parse_github_app_export(path)
            identity = parsed["identities"][0]
            self.assertEqual(identity["id"], "github:code-agent")
            self.assertEqual(identity["target_system"], "github")
            self.assertIn("source_code", {klass for permission in identity["permissions"] for klass in permission["data_classes"]})
            self.assertIn("secrets", {klass for permission in identity["permissions"] for klass in permission["data_classes"]})

    def test_github_app_permission_export_warnings_and_extra_classes(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "github-app.json"
            path.write_text(
                json.dumps(
                    {
                        "slug": "ops-app",
                        "permissions": {
                            "actions": "admin",
                            "security_events": "read",
                            "issues": "none",
                            "metadata": "custom",
                        },
                    }
                ),
                encoding="utf-8",
            )
            parsed = parse_github_app_export(path)
            identity = parsed["identities"][0]
            classes = {klass for permission in identity["permissions"] for klass in permission["data_classes"]}
            self.assertEqual(identity["id"], "github:ops-app")
            self.assertIn("production_config", classes)
            self.assertIn("security_logs", classes)
            self.assertIn("internal", classes)

            empty_path = Path(tmp) / "empty-github-app.json"
            empty_path.write_text(json.dumps({"permissions": []}), encoding="utf-8")
            self.assertTrue(parse_github_app_export(empty_path)["warnings"])

    def test_oauth_scope_export(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "slack-oauth-scopes.json"
            path.write_text(
                json.dumps(
                    {
                        "identity_id": "slack:support-agent",
                        "target_system": "slack",
                        "scopes": ["chat:write", "users:read"],
                    }
                ),
                encoding="utf-8",
            )
            parsed = parse_oauth_scope_export(path)
            identity = parsed["identities"][0]
            self.assertEqual(identity["target_system"], "slack")
            self.assertEqual(identity["scopes"], ["chat:write", "users:read"])
            self.assertIn("write", identity["permissions"][0]["actions"])

    def test_oauth_scope_export_google_and_empty_warnings(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "google-oauth-scopes.json"
            path.write_text(
                json.dumps(
                    {
                        "granted_scopes": [
                            "https://www.googleapis.com/auth/gmail.readonly",
                            "https://www.googleapis.com/auth/drive.file",
                            "profile",
                            "custom.scope",
                        ]
                    }
                ),
                encoding="utf-8",
            )
            parsed = parse_oauth_scope_export(path)
            identity = parsed["identities"][0]
            classes = {klass for permission in identity["permissions"] for klass in permission["data_classes"]}
            self.assertEqual(identity["target_system"], "google_workspace")
            self.assertIn("customer_pii", classes)
            self.assertIn("employee_pii", classes)

            empty_path = Path(tmp) / "empty-oauth.json"
            empty_path.write_text(json.dumps({"target_system": "unknown"}), encoding="utf-8")
            self.assertTrue(parse_oauth_scope_export(empty_path)["warnings"])

    def test_oauth_scope_export_infers_enterprise_targets(self):
        cases = [
            (
                "microsoft-oauth.json",
                {"scope": "https://graph.microsoft.com/Mail.Read Mail.Send Files.Read.All"},
                "microsoft_365",
                "microsoft365.Mail",
                {"read", "write"},
            ),
            (
                "github-oauth.json",
                {"scopes": ["repo", "read:org", "read:user", "reports.read"]},
                "github",
                "github.repo",
                {"read", "write"},
            ),
            (
                "jira-oauth.json",
                {"scopes": ["read:jira-work", "write:jira-work"]},
                "jira",
                "jira.jira-work",
                {"read", "write"},
            ),
            (
                "okta-oauth.json",
                {"scopes": ["okta.users.read", "okta.apps.manage"]},
                "okta",
                "okta.users",
                {"read", "write", "admin"},
            ),
        ]
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            for file_name, payload, target_system, expected_resource, expected_actions in cases:
                path = tmp_path / file_name
                path.write_text(json.dumps(payload), encoding="utf-8")
                identity = parse_oauth_scope_export(path)["identities"][0]
                actions = {action for permission in identity["permissions"] for action in permission["actions"]}
                resources = {permission["resource"] for permission in identity["permissions"]}
                self.assertEqual(identity["target_system"], target_system, file_name)
                self.assertIn(expected_resource, resources, file_name)
                self.assertTrue(expected_actions.issubset(actions), file_name)

    def test_salesforce_permission_export(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "salesforce-permissions.json"
            path.write_text(
                json.dumps(
                    {
                        "identity_id": "salesforce:support-agent",
                        "objectPermissions": [
                            {"object": "Contact", "permissionsRead": True},
                            {"object": "Case", "permissionsRead": True, "permissionsEdit": True},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            parsed = parse_salesforce_permissions_export(path)
            identity = parsed["identities"][0]
            resources = {permission["resource"] for permission in identity["permissions"]}
            self.assertIn("salesforce.Contact", resources)
            self.assertIn("salesforce.Case", resources)
            self.assertIn("customer_pii", identity["permissions"][0]["data_classes"])

    def test_salesforce_permission_export_dict_shape_and_warnings(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "salesforce-permissions.json"
            path.write_text(
                json.dumps(
                    {
                        "id": "salesforce:billing-agent",
                        "object_permissions": {
                            "Payment__c": {"actions": ["read"], "data_classes": ["financial_data"]},
                            "Invoice__c": {"allowCreate": True},
                            "Empty__c": {},
                        },
                    }
                ),
                encoding="utf-8",
            )
            parsed = parse_salesforce_permissions_export(path)
            permissions = parsed["identities"][0]["permissions"]
            self.assertEqual(len(permissions), 2)
            self.assertIn("financial_data", {klass for permission in permissions for klass in permission["data_classes"]})
            self.assertIn("billing_data", {klass for permission in permissions for klass in permission["data_classes"]})

            empty_path = Path(tmp) / "empty-salesforce.json"
            empty_path.write_text(json.dumps({"objects": [{"object": "Contact"}]}), encoding="utf-8")
            self.assertTrue(parse_salesforce_permissions_export(empty_path)["warnings"])

    def test_aws_iam_policy_export(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "aws-iam-policy.json"
            path.write_text(
                json.dumps(
                    {
                        "identity_id": "aws:agent-role",
                        "Statement": [
                            {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": "*"},
                            {"Effect": "Deny", "Action": "iam:DeleteRole", "Resource": "*"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            parsed = parse_aws_iam_policy_export(path)
            identity = parsed["identities"][0]
            self.assertEqual(identity["target_system"], "aws")
            self.assertEqual(len(identity["permissions"]), 1)
            self.assertIn("secrets", identity["permissions"][0]["data_classes"])

    def test_aws_iam_policy_export_nested_policy_and_warnings(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "aws-iam-policy.json"
            path.write_text(
                json.dumps(
                    {
                        "RoleName": "ops-agent",
                        "policy": {
                            "Statement": {
                                "Effect": "Allow",
                                "Action": ["cloudformation:UpdateStack", "codecommit:GetFile", "s3:PutObject"],
                                "Resource": ["arn:aws:s3:::agent-bucket/*"],
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            parsed = parse_aws_iam_policy_export(path)
            identity = parsed["identities"][0]
            classes = {klass for permission in identity["permissions"] for klass in permission["data_classes"]}
            self.assertEqual(identity["id"], "aws:ops-agent")
            self.assertIn("production_config", classes)
            self.assertIn("source_code", classes)
            self.assertIn("internal", classes)

            empty_path = Path(tmp) / "empty-iam.json"
            empty_path.write_text(json.dumps({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}), encoding="utf-8")
            self.assertTrue(parse_aws_iam_policy_export(empty_path)["warnings"])

    def test_kubernetes_rbac_export(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "kubernetes-rbac.json"
            path.write_text(
                json.dumps(
                    {
                        "kind": "ClusterRole",
                        "metadata": {"name": "agent-runner"},
                        "rules": [
                            {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]},
                            {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["patch"]},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            parsed = parse_kubernetes_rbac_export(path)
            identity = parsed["identities"][0]
            self.assertEqual(identity["id"], "kubernetes:agent-runner")
            self.assertIn("secrets", {klass for permission in identity["permissions"] for klass in permission["data_classes"]})
            self.assertIn("production_config", {klass for permission in identity["permissions"] for klass in permission["data_classes"]})

    def test_kubernetes_rbac_export_list_shape_and_warnings(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "kubernetes-rbac.json"
            path.write_text(
                json.dumps(
                    {
                        "items": [
                            {"kind": "ServiceAccount", "metadata": {"name": "ignored"}},
                            {
                                "kind": "Role",
                                "metadata": {"name": "viewer"},
                                "rules": [{"resources": ["events", "pods"], "verbs": ["get"]}],
                            },
                            {"kind": "Role", "metadata": {"name": "empty"}, "rules": []},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            parsed = parse_kubernetes_rbac_export(path)
            self.assertEqual({identity["id"] for identity in parsed["identities"]}, {"kubernetes:viewer", "kubernetes:empty"})
            classes = {
                klass
                for identity in parsed["identities"]
                for permission in identity["permissions"]
                for klass in permission["data_classes"]
            }
            self.assertIn("security_logs", classes)
            self.assertIn("production_config", classes)
            self.assertTrue(parsed["warnings"])

            empty_path = Path(tmp) / "empty-rbac.json"
            empty_path.write_text(json.dumps({"items": [{"kind": "ServiceAccount"}]}), encoding="utf-8")
            self.assertTrue(parse_kubernetes_rbac_export(empty_path)["warnings"])

    def test_identity_export_importers_report_malformed_recoverable_rows(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)

            github_path = tmp_path / "bad-github-app.json"
            github_path.write_text(
                json.dumps({"permissions": "bad", "repository_permissions": ["bad-row", {}]}),
                encoding="utf-8",
            )
            github_warnings = "\n".join(parse_github_app_export(github_path)["warnings"])
            self.assertIn("GitHub permissions must be an object or list", github_warnings)
            self.assertIn("GitHub repository_permissions[1] must be an object", github_warnings)
            self.assertIn("GitHub repository_permissions[2] is missing name/permission/resource", github_warnings)
            self.assertIn("no GitHub App permissions found", github_warnings)

            oauth_path = tmp_path / "bad-oauth.json"
            oauth_path.write_text(json.dumps({"scopes": {"not": "valid"}}), encoding="utf-8")
            oauth_warnings = "\n".join(parse_oauth_scope_export(oauth_path)["warnings"])
            self.assertIn("OAuth scopes must be a string or list of strings", oauth_warnings)
            self.assertIn("no OAuth scopes found", oauth_warnings)

            salesforce_path = tmp_path / "bad-salesforce.json"
            salesforce_path.write_text(
                json.dumps({"objectPermissions": ["bad-row", {"actions": ["read"]}, {"object": "Contact"}]}),
                encoding="utf-8",
            )
            salesforce_warnings = "\n".join(parse_salesforce_permissions_export(salesforce_path)["warnings"])
            self.assertIn("Salesforce object_permissions[1] must be an object", salesforce_warnings)
            self.assertIn("Salesforce object_permissions[2] is missing object/resource name", salesforce_warnings)
            self.assertIn("Salesforce object_permissions[3] for Contact has no read/write actions", salesforce_warnings)
            self.assertIn("no Salesforce object permissions found", salesforce_warnings)

            aws_path = tmp_path / "bad-aws.json"
            aws_path.write_text(
                json.dumps(
                    {
                        "Statement": [
                            "bad-row",
                            {"Effect": "Allow", "Resource": "*"},
                            {"Effect": "Allow", "Action": "s3:GetObject"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            aws = parse_aws_iam_policy_export(aws_path)
            aws_warnings = "\n".join(aws["warnings"])
            self.assertIn("AWS IAM Statement[1] must be an object", aws_warnings)
            self.assertIn("AWS IAM Statement[2] is missing Action", aws_warnings)
            self.assertIn("AWS IAM Statement[3] is missing Resource; using '*'", aws_warnings)
            self.assertEqual(aws["identities"][0]["permissions"][0]["resource"], "*")

            kubernetes_path = tmp_path / "bad-kubernetes.json"
            kubernetes_path.write_text(
                json.dumps(
                    {
                        "items": [
                            {"kind": "Role", "metadata": {"name": "bad"}, "rules": "bad"},
                            {
                                "kind": "Role",
                                "metadata": {"name": "viewer"},
                                "rules": ["bad-row", {"resources": ["pods"]}, {"verbs": ["get"]}],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            kubernetes_warnings = "\n".join(parse_kubernetes_rbac_export(kubernetes_path)["warnings"])
            self.assertIn("Kubernetes Role bad rules must be a list", kubernetes_warnings)
            self.assertIn("Kubernetes Role viewer rules[1] must be an object", kubernetes_warnings)
            self.assertIn("Kubernetes Role viewer rules[2] is missing verbs", kubernetes_warnings)
            self.assertIn("Kubernetes Role viewer rules[3] is missing resources; using '*'", kubernetes_warnings)

    def test_top_enterprise_permission_targets_normalize_to_identity_permissions(self):
        cases = [
            (
                "microsoft-365-permissions.json",
                parse_microsoft_365_permission_export,
                {"identity_id": "microsoft365:sales-agent", "graph_permissions": [{"resource": "mail", "actions": ["Mail.Read", "Mail.Send"]}]},
                "microsoft_365",
                "microsoft365.mail",
                "send",
            ),
            (
                "azure-rbac.json",
                parse_azure_rbac_export,
                {"principal_id": "release-agent", "roleAssignments": [{"scope": "/subscriptions/prod/resourceGroups/payments", "roleDefinitionName": "Contributor"}]},
                "azure",
                "azure./subscriptions/prod/resourceGroups/payments",
                "write",
            ),
            (
                "gcp-iam-policy.json",
                parse_gcp_iam_policy_export,
                {"service_account": "deploy@project.iam.gserviceaccount.com", "bindings": [{"resource": "projects/prod", "role": "roles/cloudfunctions.developer"}]},
                "gcp",
                "gcp.projects/prod",
                "write",
            ),
            (
                "dataverse-permissions.json",
                parse_dataverse_permissions_export,
                {"identity_id": "dataverse:sales-agent", "table_permissions": [{"table": "Opportunity", "privileges": ["Read", "Write"]}]},
                "dataverse",
                "dataverse.Opportunity",
                "write",
            ),
            (
                "power-platform-permissions.json",
                parse_power_platform_permissions_export,
                {"identity_id": "powerplatform:approver", "environment_permissions": [{"resource": "Approvals", "actions": ["Create"]}]},
                "power_platform",
                "powerplatform.Approvals",
                "write",
            ),
            (
                "okta-permissions.json",
                parse_okta_permissions_export,
                {"identity_id": "okta:agent", "roles": [{"resource": "users", "role": "USER_ADMIN"}]},
                "okta",
                "okta.users",
                "admin",
            ),
            (
                "jira-permissions.json",
                parse_jira_permissions_export,
                {"identity_id": "jira:agent", "project_permissions": [{"project": "SEC", "permissions": ["Browse Projects", "Edit Issues"]}]},
                "jira",
                "jira.SEC",
                "write",
            ),
            (
                "confluence-permissions.json",
                parse_confluence_permissions_export,
                {"identity_id": "confluence:agent", "space_permissions": [{"resource": "ENG", "actions": ["read", "write"]}]},
                "confluence",
                "confluence.ENG",
                "write",
            ),
            (
                "zendesk-permissions.json",
                parse_zendesk_permissions_export,
                {"identity_id": "zendesk:agent", "role_permissions": [{"resource": "tickets", "actions": ["read", "update"]}]},
                "zendesk",
                "zendesk.tickets",
                "write",
            ),
            (
                "servicenow-permissions.json",
                parse_servicenow_permissions_export,
                {"identity_id": "servicenow:agent", "table_permissions": [{"table": "change_request", "actions": ["read", "write"]}]},
                "servicenow",
                "servicenow.change_request",
                "write",
            ),
            (
                "snowflake-grants.json",
                parse_snowflake_grants_export,
                {"identity_id": "snowflake:agent_role", "grants": [{"database": "CUSTOMER_DB", "privileges": ["USAGE", "SELECT"]}]},
                "snowflake",
                "snowflake.CUSTOMER_DB",
                "read",
            ),
            (
                "databricks-permissions.json",
                parse_databricks_permissions_export,
                {"identity_id": "databricks:job-runner", "object_permissions": [{"resource": "jobs/payment-etl", "permission": "CAN_MANAGE"}]},
                "databricks",
                "databricks.jobs/payment-etl",
                "admin",
            ),
            (
                "stripe-permissions.json",
                parse_stripe_permissions_export,
                {"identity_id": "stripe:refund-agent", "restricted_key_permissions": [{"resource": "refunds", "actions": ["read", "write"]}]},
                "stripe",
                "stripe.refunds",
                "write",
            ),
            (
                "netsuite-permissions.json",
                parse_netsuite_permissions_export,
                {"identity_id": "netsuite:finance-agent", "record_permissions": [{"resource": "Vendor Payment", "actions": ["Create"]}]},
                "netsuite",
                "netsuite.Vendor Payment",
                "write",
            ),
        ]
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            for file_name, parser, payload, target_system, expected_resource, expected_action in cases:
                path = tmp_path / file_name
                path.write_text(json.dumps(payload), encoding="utf-8")
                parsed = parser(path)
                identity = parsed["identities"][0]
                self.assertEqual(identity["target_system"], target_system, file_name)
                self.assertEqual(identity["permissions"][0]["resource"], expected_resource, file_name)
                self.assertIn(expected_action, identity["permissions"][0]["actions"], file_name)
                self.assertTrue(identity["permissions"][0]["data_classes"], file_name)
                self.assertEqual(parsed["warnings"], [], file_name)

    def test_generic_enterprise_permission_parser_warns_on_bad_rows(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "azure-rbac.json"
            path.write_text(json.dumps({"roleAssignments": [42, {"actions": ["read"]}]}), encoding="utf-8")
            parsed = parse_azure_rbac_export(path)
            joined_warnings = "\n".join(parsed["warnings"])
            self.assertIn("Azure RBAC roleAssignments[1] must be an object or string", joined_warnings)
            self.assertIn("Azure RBAC permission[1] is missing resource", joined_warnings)
            self.assertIn("no Azure RBAC permissions found", joined_warnings)


if __name__ == "__main__":
    unittest.main()
