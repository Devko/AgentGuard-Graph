import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import write_json
from agentguard_graph.errors import EvidenceLoadError
from agentguard_graph.adapters.openapi import parse_openapi


class OpenAPIAdapterTests(unittest.TestCase):
    def test_openapi_json_operation_parsing(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "openapi.json"
            write_json(
                path,
                {
                    "openapi": "3.0.0",
                    "info": {"title": "Support API", "version": "2026-05-17"},
                    "paths": {
                        "/customers/{id}": {
                            "get": {
                                "operationId": "getCustomer",
                                "summary": "Read customer profile",
                                "security": [{"oauth": ["customers.read"]}],
                                "responses": {
                                    "200": {
                                        "description": "Customer profile",
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {"email": {"type": "string"}, "phone": {"type": "string"}},
                                                }
                                            }
                                        },
                                    }
                                },
                            }
                        },
                        "/payments/refund": {
                            "post": {
                                "operationId": "createRefund",
                                "summary": "Create payment refund",
                                "requestBody": {
                                    "content": {
                                        "application/json": {
                                            "schema": {
                                                "type": "object",
                                                "properties": {"amount": {"type": "number"}, "card_last4": {"type": "string"}},
                                            }
                                        }
                                    }
                                },
                            }
                        },
                    },
                },
            )
            parsed = parse_openapi(path)
            tools = {tool["id"]: tool for tool in parsed["tools"]}
            self.assertIn("getCustomer", tools)
            self.assertIn("sensitive_read", tools["getCustomer"]["risk_tags"])
            self.assertEqual(tools["getCustomer"]["security_scopes"], ["oauth:customers.read"])
            self.assertEqual(tools["getCustomer"]["api_document_id"], "openapi.json")
            self.assertEqual(tools["getCustomer"]["api_title"], "Support API")
            self.assertEqual(tools["getCustomer"]["api_version"], "2026-05-17")
            self.assertIn("customer_pii", tools["getCustomer"]["response_data_classes"])
            self.assertIn("customer_pii", tools["getCustomer"]["data_classes"])
            self.assertIn("financial_action", tools["createRefund"]["risk_tags"])
            self.assertIn("write_action", tools["createRefund"]["risk_tags"])
            self.assertIn("billing_data", tools["createRefund"]["request_data_classes"])
            self.assertIn("financial_data", tools["createRefund"]["data_classes"])

    def test_openapi_directory_and_empty_path(self):
        self.assertEqual(parse_openapi(None)["tools"], [])
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            write_json(tmp_path / "one.json", {"openapi": "3.0.0", "paths": {}})
            (tmp_path / "skipped.yaml").write_text("openapi: 3.0.0\n", encoding="utf-8")
            write_json(
                tmp_path / "two.json",
                {
                    "openapi": "3.0.0",
                    "paths": {
                        "/messages/send": {
                            "post": {"operationId": "sendSlackMessage", "summary": "Send Slack message"}
                        }
                    },
                },
            )
            parsed = parse_openapi(tmp_path)
            self.assertEqual([tool["id"] for tool in parsed["tools"]], ["sendSlackMessage"])
            self.assertIn("skipped.yaml: OpenAPI YAML input is not supported; skipped", parsed["warnings"])

    def test_openapi_empty_directory_warns(self):
        with TemporaryDirectory() as tmp:
            parsed = parse_openapi(Path(tmp))
            self.assertEqual(parsed["tools"], [])
            self.assertTrue(any("no JSON OpenAPI files found" in warning for warning in parsed["warnings"]))

    def test_openapi_directory_skips_bad_json_with_warning(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "bad.json").write_text("{bad", encoding="utf-8")
            write_json(
                tmp_path / "good.json",
                {
                    "openapi": "3.0.0",
                    "paths": {
                        "/messages/send": {
                            "post": {"operationId": "sendMessage", "summary": "Send message"}
                        }
                    },
                },
            )

            parsed = parse_openapi(tmp_path)
            self.assertEqual([tool["id"] for tool in parsed["tools"]], ["sendMessage"])
            joined_warnings = "\n".join(parsed["warnings"])
            self.assertIn("bad.json: skipped invalid OpenAPI JSON", joined_warnings)
            self.assertIn("invalid JSON", joined_warnings)

    def test_openapi_single_bad_json_remains_strict_error(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("{bad", encoding="utf-8")
            with self.assertRaises(EvidenceLoadError) as context:
                parse_openapi(path)
            self.assertIn("invalid JSON", str(context.exception))

    def test_openapi_risk_heuristics_cover_v0_1_vocabulary(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "openapi.json"
            write_json(
                path,
                {
                    "openapi": "3.1.0",
                    "servers": [{"url": "https://api.github.example"}],
                    "security": [{"oauth": ["repo.write"]}],
                    "paths": {
                        "/deploy/terraform/apply": {
                            "post": {"operationId": "applyTerraform", "summary": "Apply production Terraform"}
                        },
                        "/secrets/token": {
                            "get": {"operationId": "getToken", "summary": "Read secret token"}
                        },
                        "/commands": {
                            "post": {"operationId": "runCommand", "summary": "Run command"}
                        },
                        "/users/{id}/profile": {
                            "patch": {"operationId": "updateUserProfile", "summary": "Update user profile"}
                        },
                    },
                },
            )
            tools = {tool["id"]: tool for tool in parse_openapi(path)["tools"]}
            self.assertIn("production_write", tools["applyTerraform"]["risk_tags"])
            self.assertIn("secret_access", tools["getToken"]["risk_tags"])
            self.assertIn("command_execution", tools["runCommand"]["risk_tags"])
            self.assertIn("sensitive_write", tools["updateUserProfile"]["risk_tags"])
            self.assertEqual(tools["runCommand"]["target_system"], "github")

    def test_openapi_yaml_has_useful_error(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "openapi.yaml"
            path.write_text("openapi: 3.0.0\n", encoding="utf-8")
            with self.assertRaises(EvidenceLoadError) as context:
                parse_openapi(path)
            self.assertIn("YAML input is not supported", str(context.exception))

    def test_openapi_warns_and_skips_non_operations(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "openapi.json"
            write_json(
                path,
                {
                    "paths": {
                        "/not-object": [],
                        "/mixed": {
                            "parameters": [],
                            "trace": {"operationId": "traceThing"},
                            "get": "not an operation",
                            "post": {
                                "operationId": "sendWebhook",
                                "summary": "Send webhook",
                                "security": [{"apiKey": "required"}, "not-a-requirement"],
                            },
                            "delete": {
                                "summary": "Delete customer account",
                                "security": "not-a-list",
                            },
                        },
                    },
                },
            )
            parsed = parse_openapi(path)
            tools = {tool["id"]: tool for tool in parsed["tools"]}
            joined_warnings = "\n".join(parsed["warnings"])
            self.assertIn("OpenAPI version is not 3.x or is missing", joined_warnings)
            self.assertIn("OpenAPI path /not-object must be an object", joined_warnings)
            self.assertIn("OpenAPI operation GET /mixed must be an object", joined_warnings)
            self.assertIn("sendWebhook", tools)
            self.assertIn("apiKey", tools["sendWebhook"]["security_scopes"])
            self.assertIn("delete__mixed", tools)
            self.assertIn("destructive_action", tools["delete__mixed"]["risk_tags"])

    def test_openapi_non_object_paths_warns_without_crashing(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "openapi.json"
            write_json(path, {"openapi": "3.0.0", "paths": []})

            parsed = parse_openapi(path)
            self.assertEqual(parsed["tools"], [])
            self.assertIn("openapi.json: OpenAPI paths must be an object", parsed["warnings"])


if __name__ == "__main__":
    unittest.main()
