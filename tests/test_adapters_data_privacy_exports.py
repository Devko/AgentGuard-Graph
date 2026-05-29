import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from agentguard_graph.adapters.data_privacy_exports import (
    parse_data_catalog_export,
    parse_dlp_export,
    parse_sensitivity_label_export,
    parse_table_classification_export,
)


def write_json(path: Path, data: object) -> str:
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


class DataPrivacyExportAdapterTests(unittest.TestCase):
    def test_data_catalog_export_normalizes_assets(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "purview-assets.json"
            result = parse_data_catalog_export(
                write_json(
                    path,
                    {
                        "assets": [
                            {
                                "qualifiedName": "salesforce.Contact",
                                "name": "Contact",
                                "system": "salesforce",
                                "classifications": ["Customer PII", "Confidential"],
                                "owner": "data-platform",
                            }
                        ]
                    },
                )
            )

        item = result["data_sources"][0]
        self.assertEqual(item["id"], "salesforce.Contact")
        self.assertEqual(item["target_system"], "salesforce")
        self.assertIn("customer_pii", item["data_classes"])
        self.assertEqual(item["sensitivity"], "high")
        self.assertEqual(item["owner"], "data-platform")

    def test_dlp_export_normalizes_findings(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "dlp-findings.json"
            result = parse_dlp_export(
                write_json(
                    path,
                    {
                        "findings": [
                            {
                                "resourceName": "bigquery://prod.customers",
                                "column": "email",
                                "infoType": {"name": "EMAIL_ADDRESS"},
                                "likelihood": "VERY_LIKELY",
                            }
                        ]
                    },
                )
            )

        item = result["data_sources"][0]
        self.assertEqual(item["id"], "bigquery://prod.customers.email")
        self.assertIn("customer_pii", item["data_classes"])
        self.assertEqual(item["source_kind"], "dlp_export")

    def test_sensitivity_label_export_normalizes_labels(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "sensitivity-labels.json"
            result = parse_sensitivity_label_export(
                write_json(
                    path,
                    {
                        "labeledResources": [
                            {
                                "resourceName": "sharepoint://Finance/VendorPayments.xlsx",
                                "sensitivityLabel": {"name": "Highly Confidential - Payment"},
                                "owner": "finance-data",
                            }
                        ]
                    },
                )
            )

        item = result["data_sources"][0]
        self.assertEqual(item["sensitivity"], "critical")
        self.assertIn("payment_data", item["data_classes"])
        self.assertEqual(item["owner"], "finance-data")

    def test_table_classification_export_normalizes_fields(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "table-classifications.json"
            result = parse_table_classification_export(
                write_json(
                    path,
                    {
                        "tables": [
                            {
                                "database": "warehouse",
                                "table": "source_repositories",
                                "platform": "snowflake",
                                "columns": {
                                    "repo_url": {"classification": "Source Code"},
                                    "deploy_token": {"classification": "Secret"},
                                },
                            }
                        ]
                    },
                )
            )

        item = result["data_sources"][0]
        self.assertEqual(item["id"], "warehouse.source_repositories")
        self.assertEqual(item["target_system"], "snowflake")
        self.assertIn("source_code", item["data_classes"])
        self.assertIn("secrets", item["data_classes"])
        self.assertEqual(len(item["fields"]), 2)


if __name__ == "__main__":
    unittest.main()
