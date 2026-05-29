import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import sample_paths, write_json
from agentguard_graph.adapters.identity import parse_identity


class IdentityAdapterTests(unittest.TestCase):
    def test_identity_permission_parsing(self):
        parsed = parse_identity(sample_paths("support-agent")["identity"])
        identities = {identity["id"]: identity for identity in parsed["identities"]}
        salesforce = identities["salesforce:support-agent-connected-app"]
        self.assertEqual(salesforce["target_system"], "salesforce")
        self.assertEqual(salesforce["permissions"][0]["data_classes"], ["customer_pii"])

    def test_identity_parser_reports_recoverable_malformed_entries(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "identity.json"
            write_json(
                path,
                {
                    "identities": [
                        "not-an-identity",
                        {"scopes": "repo", "permissions": "not-a-list"},
                        {
                            "id": "github:agent",
                            "permissions": [
                                [],
                                {"actions": "read", "data_classes": "source_code"},
                            ],
                        },
                    ]
                },
            )

            parsed = parse_identity(path)

            identities = {identity["id"]: identity for identity in parsed["identities"] if identity["id"]}
            self.assertEqual(identities["github:agent"]["permissions"][0]["actions"], ["read"])
            self.assertEqual(identities["github:agent"]["permissions"][0]["data_classes"], ["source_code"])
            joined_warnings = "\n".join(parsed["warnings"])
            self.assertIn("identities[0] must be an object", joined_warnings)
            self.assertIn("identities[1] is missing id", joined_warnings)
            self.assertIn("scopes should be a list", joined_warnings)
            self.assertIn("permissions must be a list", joined_warnings)
            self.assertIn("permissions[0] must be an object", joined_warnings)
            self.assertIn("is missing resource", joined_warnings)
            self.assertIn("actions should be a list", joined_warnings)
            self.assertIn("data_classes should be a list", joined_warnings)


if __name__ == "__main__":
    unittest.main()
