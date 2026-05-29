import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import sample_paths, write_json
from agentguard_graph.adapters.data_catalog import parse_data_catalog


class DataCatalogAdapterTests(unittest.TestCase):
    def test_data_catalog_parsing(self):
        parsed = parse_data_catalog(sample_paths("support-agent")["data_catalog"])
        data = {item["id"]: item for item in parsed["data_sources"]}
        self.assertEqual(data["salesforce.Contact"]["sensitivity"], "high")
        self.assertIn("customer_pii", data["support-vector-store"]["data_classes"])
        self.assertEqual(data["salesforce.Contact"]["source_kind"], "data_catalog")

    def test_data_catalog_parser_reports_recoverable_malformed_entries(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "data-catalog.json"
            write_json(
                path,
                {
                    "data_sources": [
                        [],
                        {"id": "crm.contacts", "data_classes": "customer_pii", "sensitivity": "secret"},
                        {"name": "Missing id"},
                    ]
                },
            )

            parsed = parse_data_catalog(path)

            data_sources = {item["id"]: item for item in parsed["data_sources"] if item["id"]}
            self.assertEqual(data_sources["crm.contacts"]["sensitivity"], "unknown")
            self.assertEqual(data_sources["crm.contacts"]["data_classes"], ["customer_pii"])
            joined_warnings = "\n".join(parsed["warnings"])
            self.assertIn("data_sources[0] must be an object", joined_warnings)
            self.assertIn("data_classes should be a list", joined_warnings)
            self.assertIn("sensitivity normalized to unknown", joined_warnings)
            self.assertIn("data_sources[2] is missing id", joined_warnings)


if __name__ == "__main__":
    unittest.main()
