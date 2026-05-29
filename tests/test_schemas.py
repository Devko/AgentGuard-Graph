import unittest
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import ROOT, write_json
from agentguard_graph.errors import EvidenceLoadError
from agentguard_graph.schemas import (
    as_list,
    infer_target_system,
    load_json_file,
    load_jsonl_file,
    node_id,
    string_list,
)


class SchemaHelperTests(unittest.TestCase):
    def test_json_loader_optional_and_errors(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            self.assertEqual(load_json_file(tmp_path / "missing.json", required=False), {})
            bad = tmp_path / "bad.json"
            bad.write_text("{bad", encoding="utf-8")
            with self.assertRaises(EvidenceLoadError):
                load_json_file(bad)
            array = tmp_path / "array.json"
            array.write_text("[]", encoding="utf-8")
            with self.assertRaises(EvidenceLoadError):
                load_json_file(array)
            invalid_utf8 = tmp_path / "invalid-utf8.json"
            invalid_utf8.write_bytes(b'{"name":"\xff"}')
            with self.assertRaises(EvidenceLoadError) as context:
                load_json_file(invalid_utf8)
            self.assertIn("cannot decode as UTF-8", str(context.exception))

    def test_jsonl_loader_optional_and_non_object_line(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            self.assertEqual(load_jsonl_file(tmp_path / "missing.jsonl", required=False), [])
            path = tmp_path / "events.jsonl"
            path.write_text("[]\n", encoding="utf-8")
            with self.assertRaises(EvidenceLoadError):
                load_jsonl_file(path)
            invalid_utf8 = tmp_path / "invalid-utf8.jsonl"
            invalid_utf8.write_bytes(b'{"event_type":"agent.tool_call","agent":"\xff"}\n')
            with self.assertRaises(EvidenceLoadError) as context:
                load_jsonl_file(invalid_utf8)
            self.assertIn("cannot decode as UTF-8", str(context.exception))

    def test_small_helpers(self):
        self.assertEqual(as_list("x"), ["x"])
        self.assertEqual(as_list(None), [])
        self.assertEqual(string_list([1, "a", None]), ["1", "a"])
        self.assertEqual(node_id("agent", "a"), "agent:a")
        self.assertEqual(infer_target_system("github.create_pr"), "github")
        self.assertEqual(infer_target_system("unknown thing"), "unknown")

    def test_valid_json_loader(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "ok.json"
            write_json(path, {"schema_version": "0.1"})
            self.assertEqual(load_json_file(path)["schema_version"], "0.1")

    def test_checked_in_schemas_are_valid_json_with_required_keys(self):
        for path in (ROOT / "schemas").glob("*.schema.json"):
            schema = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertIn("title", schema)
            self.assertIn("type", schema)

    def test_report_schema_declares_operational_contract_fields(self):
        schema = json.loads((ROOT / "schemas" / "findings.schema.json").read_text(encoding="utf-8"))
        required = set(schema["required"])
        self.assertIn("review_decision", required)
        self.assertIn("review_brief", required)
        self.assertIn("evidence_manifest", required)
        self.assertIn("evidence_guide", required)
        self.assertIn("remediation_plan", required)
        self.assertIn("iam_analysis", required)
        self.assertIn("offline_control_analysis", required)
        self.assertIn("policy_analysis", required)
        self.assertIn("runtime_reconstruction", required)
        self.assertIn("runtime_reconstruction", schema["properties"])
        self.assertEqual(schema["properties"]["evidence_manifest"]["$ref"], "#/$defs/evidence_manifest")
        self.assertIn("evidence_guide", schema["properties"])
        self.assertEqual(schema["properties"]["remediation_plan"]["$ref"], "#/$defs/remediation_plan")
        self.assertIn("iam_analysis", schema["properties"])
        self.assertIn("offline_control_analysis", schema["properties"])
        offline_required = set(schema["properties"]["offline_control_analysis"]["required"])
        self.assertIn("roadmap", offline_required)
        offline_properties = schema["properties"]["offline_control_analysis"]["properties"]
        self.assertEqual(offline_properties["summary"]["$ref"], "#/$defs/offline_summary")
        self.assertEqual(offline_properties["tool_inventory"]["items"]["$ref"], "#/$defs/offline_tool_inventory_row")
        self.assertEqual(offline_properties["generic_tools"]["items"]["$ref"], "#/$defs/offline_tool_inventory_row")
        self.assertEqual(offline_properties["agent_tool_controls"]["items"]["$ref"], "#/$defs/offline_agent_tool_control_row")
        self.assertEqual(offline_properties["policy_control_gaps"]["items"]["$ref"], "#/$defs/offline_policy_control_gap")
        self.assertEqual(offline_properties["prompt_security_boundaries"]["items"]["$ref"], "#/$defs/offline_prompt_security_boundary")
        self.assertEqual(offline_properties["prompt_boundary_risks"]["items"]["$ref"], "#/$defs/offline_prompt_boundary_risk")
        self.assertEqual(offline_properties["roadmap"]["items"]["$ref"], "#/$defs/offline_roadmap_item")
        for definition in [
            "offline_summary",
            "offline_tool_inventory_row",
            "offline_agent_tool_control_row",
            "offline_policy_control_gap",
            "offline_prompt_security_boundary",
            "offline_prompt_boundary_risk",
            "offline_roadmap_item",
            "offline_control_name",
            "evidence_manifest",
            "remediation_plan",
            "remediation_rollup",
            "remediation_action",
        ]:
            self.assertIn(definition, schema["$defs"])
        self.assertIn("approval_required", schema["$defs"]["offline_control_name"]["enum"])
        roadmap_required = set(schema["$defs"]["offline_roadmap_item"]["required"])
        self.assertIn("acceptance_criteria", roadmap_required)
        self.assertIn("evidence_needed", roadmap_required)
        remediation_required = set(schema["$defs"]["remediation_plan"]["required"])
        self.assertIn("actions", remediation_required)
        remediation_action_required = set(schema["$defs"]["remediation_action"]["required"])
        self.assertIn("owner", remediation_action_required)
        self.assertIn("target", remediation_action_required)
        self.assertIn("category", remediation_action_required)
        self.assertIn("related_finding_ids", remediation_action_required)
        self.assertIn("related_gap_ids", remediation_action_required)
        self.assertIn("policy_analysis", schema["properties"])
        policy_required = set(schema["properties"]["policy_analysis"]["required"])
        policy_properties = schema["properties"]["policy_analysis"]["properties"]
        self.assertIn("rule_risks", policy_required)
        self.assertEqual(policy_properties["rule_risks"]["items"]["$ref"], "#/$defs/policy_rule_risk")
        policy_rule_risk_types = set(schema["$defs"]["policy_rule_risk"]["properties"]["type"]["enum"])
        self.assertIn("unmatched_policy_rule", policy_rule_risk_types)
        self.assertIn("ineffective_control_rule", policy_rule_risk_types)
        finding_required = set(schema["$defs"]["finding"]["required"])
        path_required = set(schema["$defs"]["attack_path"]["required"])
        for field in [
            "path_state",
            "evidence_quality",
            "runtime_observation",
            "remediation",
            "operational_context",
            "risk_status",
            "accepted_risk",
            "visibility_gap_priorities",
            "raw_points",
        ]:
            self.assertIn(field, finding_required)
            self.assertIn(field, path_required)
        self.assertIn("accepted_risk", schema["$defs"])
        self.assertIn("policy_rule_risk", schema["$defs"])

    def test_evidence_pack_examples_are_valid_json(self):
        example_root = ROOT / "schemas" / "examples"
        for pack in ["minimal", "typical", "high-fidelity"]:
            pack_root = example_root / pack
            self.assertTrue(pack_root.is_dir(), pack)
            for name in ["agentguard.json", "mcp-servers.json", "identity.json", "data-catalog.json", "approval-policy.json"]:
                payload = json.loads((pack_root / name).read_text(encoding="utf-8"))
                self.assertEqual(payload["schema_version"], "0.1")
            events_path = pack_root / "events.jsonl"
            self.assertTrue(events_path.exists(), pack)
            for line in events_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self.assertIsInstance(json.loads(line), dict)


if __name__ == "__main__":
    unittest.main()
