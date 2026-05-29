import contextlib
import io
import json
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import ROOT, load_report
from agentguard_graph.cli import main
from agentguard_graph.compare import compare_reports, render_compare_markdown


class CompareReportTests(unittest.TestCase):
    def test_compare_reports_classifies_new_resolved_and_regressed_findings(self):
        base = load_report("support-agent")
        head = deepcopy(base)
        common_id = base["findings"][1]["id"]
        resolved_id = base["findings"][2]["id"]
        head["findings"][1]["score"] = min(int(head["findings"][1]["score"]) + 10, 100)
        head["findings"][1]["tier"] = "urgent"
        new_finding = deepcopy(head["findings"][1])
        new_finding["id"] = "finding-new-risk"
        new_finding["title"] = "New high-risk path"
        new_finding["score"] = 91
        new_finding["tier"] = "urgent"
        head["findings"] = [finding for finding in head["findings"] if finding["id"] != resolved_id]
        head["findings"].append(new_finding)
        head["visibility_gaps"].append(
            {
                "id": "gap-new",
                "type": "target_system_permissions_unknown",
                "target": "github:code-agent",
                "reason": "New permission gap",
                "requested_evidence": "GitHub App permission export",
                "severity": "high",
                "priority": "high_gap",
                "affected_findings": ["finding-new-risk"],
            }
        )

        result = compare_reports(base, head, base_label="old", head_label="new")

        self.assertEqual(result["compare"]["base"]["label"], "old")
        self.assertEqual(result["compare"]["head"]["label"], "new")
        self.assertEqual(result["summary"]["new_findings"], 1)
        self.assertEqual(result["summary"]["resolved_findings"], 1)
        self.assertEqual(result["summary"]["regressed_findings"], 1)
        self.assertEqual(result["summary"]["new_visibility_gaps"], 1)
        self.assertEqual(result["review"]["decision"], "regressed")
        changed_by_id = {item["id"]: item for item in result["findings"]["changed"]}
        self.assertEqual(changed_by_id[common_id]["status"], "regressed")
        self.assertEqual(result["findings"]["new"][0]["status"], "new")
        self.assertEqual(result["findings"]["resolved"][0]["status"], "resolved")

        markdown = render_compare_markdown(result)
        self.assertIn("AgentGuard Graph Compare", markdown)
        self.assertIn("New high-risk path", markdown)
        self.assertIn("Review regressed findings", markdown)

    def test_compare_cli_writes_json_and_markdown(self):
        base = load_report("coding-agent")
        head = deepcopy(base)
        removed = head["findings"].pop()

        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            base_path = tmp_path / "base.json"
            head_path = tmp_path / "head.json"
            out_path = tmp_path / "compare.json"
            markdown_path = tmp_path / "compare.md"
            base_path.write_text(json.dumps(base), encoding="utf-8")
            head_path.write_text(json.dumps(head), encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    main(
                        [
                            "compare",
                            "--base",
                            str(base_path),
                            "--head",
                            str(head_path),
                            "--base-label",
                            "before",
                            "--head-label",
                            "after",
                            "--out",
                            str(out_path),
                            "--markdown",
                            str(markdown_path),
                        ]
                    ),
                    0,
                )

            self.assertIn("compare summary:", stdout.getvalue())
            report = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["resolved_findings"], 1)
            self.assertEqual(report["findings"]["resolved"][0]["id"], removed["id"])
            self.assertIn("Resolved Findings", markdown_path.read_text(encoding="utf-8"))

    def test_compare_reports_tracks_accepted_risk_changes(self):
        base = load_report("support-agent")
        head = deepcopy(base)
        accepted = head["findings"][0]
        accepted["risk_status"] = "accepted"
        accepted["accepted_risk"] = {
            "status": "accepted",
            "accepted": True,
            "expired": False,
            "id": "risk-001",
            "owner": "appsec",
            "reason": "Temporary exception.",
            "ticket": "SEC-1",
            "expires_at": "2999-12-31",
        }

        result = compare_reports(base, head)

        self.assertEqual(result["summary"]["head_accepted_risk_findings"], 1)
        changed = {item["id"]: item for item in result["findings"]["changed"]}
        self.assertIn(accepted["id"], changed)
        self.assertEqual(changed[accepted["id"]]["status"], "changed")
        self.assertEqual(changed[accepted["id"]]["head"]["risk_status"], "accepted")
        self.assertIn("Accepted risk", render_compare_markdown(result))

    def test_compare_reports_summarizes_manifest_and_remediation_drift(self):
        base = {
            "findings": [],
            "attack_paths": [],
            "visibility_gaps": [],
            "evidence_manifest": {
                "status": "present",
                "summary": {
                    "checked_count": 2,
                    "changed_count": 1,
                    "missing_count": 0,
                    "unmanifested_count": 0,
                },
                "errors": [],
            },
            "remediation_plan": {
                "summary": {
                    "actions": 2,
                    "p1": 1,
                    "p2": 1,
                    "p3": 0,
                    "owners": 2,
                    "systems": 1,
                    "categories": 2,
                    "by_owner": {"appsec": 1, "identity": 1},
                    "by_system": {"github": 2},
                    "by_category": {"egress": 1, "identity": 1},
                },
                "actions": [
                    {"id": "action-1", "priority": "P1"},
                    {"id": "action-2", "priority": "P2"},
                ],
            },
        }
        head = deepcopy(base)
        head["evidence_manifest"] = {
            "status": "present",
            "summary": {
                "checked_count": 3,
                "changed_count": 0,
                "missing_count": 1,
                "unmanifested_count": 2,
            },
            "errors": ["cannot read evidence manifest"],
        }
        head["remediation_plan"] = {
            "summary": {
                "actions": 3,
                "p1": 2,
                "p2": 0,
                "p3": 1,
                "owners": 2,
                "systems": 2,
                "categories": 2,
                "by_owner": {"appsec": 2, "privacy": 1},
                "by_system": {"github": 2, "salesforce": 1},
                "by_category": {"egress": 2, "data_protection": 1},
            },
            "actions": [
                {"id": "action-2", "priority": "P1"},
                {"id": "action-3", "priority": "P1"},
                {"id": "action-4", "priority": "P3"},
            ],
        }

        result = compare_reports(base, head)

        manifest = result["evidence_manifest"]
        self.assertTrue(manifest["has_drift"])
        self.assertEqual(manifest["base"]["checked_count"], 2)
        self.assertEqual(manifest["head"]["errors_count"], 1)
        self.assertEqual(manifest["deltas"]["checked_count"], 1)
        self.assertEqual(manifest["deltas"]["changed_count"], -1)
        self.assertEqual(result["summary"]["evidence_manifest_missing_delta"], 1)

        remediation = result["remediation_plan"]
        self.assertEqual(remediation["base"]["actions"], 2)
        self.assertEqual(remediation["head"]["actions"], 3)
        self.assertEqual(remediation["deltas"]["p1"], 1)
        self.assertEqual(remediation["deltas"]["p2"], -1)
        self.assertEqual(remediation["new_action_ids"], ["action-3", "action-4"])
        self.assertEqual(remediation["resolved_action_ids"], ["action-1"])
        self.assertEqual(remediation["owner_count_changes"]["appsec"], {"base": 1, "head": 2, "delta": 1})
        self.assertEqual(remediation["owner_count_changes"]["identity"], {"base": 1, "head": 0, "delta": -1})
        self.assertEqual(remediation["system_count_changes"]["salesforce"], {"base": 0, "head": 1, "delta": 1})
        self.assertEqual(remediation["category_count_changes"]["data_protection"], {"base": 0, "head": 1, "delta": 1})
        self.assertEqual(result["summary"]["new_remediation_actions"], 2)
        self.assertEqual(result["summary"]["resolved_remediation_actions"], 1)

        markdown = render_compare_markdown(result)
        self.assertIn("Evidence Manifest Drift", markdown)
        self.assertIn("Remediation Plan Drift", markdown)
        self.assertIn("Checked files: 2 -> 3 (+1)", markdown)
        self.assertIn("P1 / P2 / P3 deltas: +1 / -1 / +1", markdown)

    def test_compare_reports_handles_older_reports_without_manifest_or_remediation(self):
        result = compare_reports({"findings": []}, {"findings": []})

        self.assertEqual(result["evidence_manifest"]["base"]["status"], "not_provided")
        self.assertEqual(result["evidence_manifest"]["head"]["status"], "not_provided")
        self.assertFalse(result["evidence_manifest"]["has_drift"])
        self.assertEqual(result["remediation_plan"]["base"]["actions"], 0)
        self.assertEqual(result["remediation_plan"]["head"]["actions"], 0)
        self.assertEqual(result["summary"]["remediation_actions_delta"], 0)
        self.assertIn("Evidence Manifest Drift", render_compare_markdown(result))

    def test_compare_cli_accepts_evidence_pack_directories(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            out_path = tmp_path / "compare.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    main(
                        [
                            "compare",
                            "--base",
                            str(ROOT / "samples" / "support-agent"),
                            "--head",
                            str(ROOT / "samples" / "coding-agent"),
                            "--out",
                            str(out_path),
                        ]
                    ),
                    0,
                )

            report = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(report["compare"]["base"]["source_type"], "evidence_pack")
            self.assertEqual(report["compare"]["head"]["source_type"], "evidence_pack")
            self.assertGreater(report["summary"]["base_findings"], 0)
            self.assertGreater(report["summary"]["head_findings"], 0)
            self.assertIn("compare summary:", stdout.getvalue())

    def test_compare_cli_rejects_malformed_report(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            base_path = tmp_path / "base.json"
            head_path = tmp_path / "head.json"
            base_path.write_text("[]", encoding="utf-8")
            head_path.write_text(json.dumps(load_report("support-agent")), encoding="utf-8")

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(
                    main(
                        [
                            "compare",
                            "--base",
                            str(base_path),
                            "--head",
                            str(head_path),
                            "--out",
                            str(tmp_path / "compare.json"),
                        ]
                    ),
                    2,
                )
            self.assertIn("report must be a JSON object", stderr.getvalue())

    def test_compare_cli_rejects_invalid_evidence_pack_directory(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            empty_pack = tmp_path / "empty-pack"
            empty_pack.mkdir()

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(
                    main(
                        [
                            "compare",
                            "--base",
                            str(empty_pack),
                            "--head",
                            str(ROOT / "samples" / "support-agent"),
                            "--out",
                            str(tmp_path / "compare.json"),
                        ]
                    ),
                    2,
                )
            self.assertIn("cannot build base report from evidence pack", stderr.getvalue())
            self.assertIn("compare base requires agent evidence", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
