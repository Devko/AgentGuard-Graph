import unittest

from _helpers import load_report
from agentguard_graph.remediation import build_remediation_plan


class RemediationPlanTests(unittest.TestCase):
    def test_report_plan_routes_actions_by_owner_system_and_category(self):
        report = load_report("support-agent")
        plan = report["remediation_plan"]

        self.assertGreater(plan["summary"]["actions"], 0)
        self.assertGreaterEqual(plan["summary"]["p1"], 1)
        self.assertTrue(plan["owner_rollups"])
        self.assertTrue(plan["system_rollups"])
        self.assertTrue(plan["category_rollups"])

        action = plan["actions"][0]
        for key in ["id", "priority", "owner", "target", "category", "reason", "related_finding_ids", "related_gap_ids"]:
            self.assertIn(key, action)
        self.assertTrue(action.get("suggested_next_command") or action.get("requested_evidence"))

    def test_plan_is_deterministic_for_same_inputs(self):
        report = load_report("support-agent")
        kwargs = {
            "findings": report["findings"],
            "visibility_gaps": report["visibility_gaps"],
            "offline_control_analysis": report["offline_control_analysis"],
            "policy_analysis": report["policy_analysis"],
            "iam_analysis": report["iam_analysis"],
            "privacy_analysis": report["privacy_analysis"],
            "evidence_guide": report["evidence_guide"],
        }
        first = build_remediation_plan(
            {},
            **kwargs,
        )
        second = build_remediation_plan(
            {},
            **kwargs,
        )

        self.assertEqual([item["id"] for item in first["actions"]], [item["id"] for item in second["actions"]])
        self.assertEqual(first["summary"]["actions"], second["summary"]["actions"])

    def test_evidence_guide_missing_evidence_can_stand_alone(self):
        plan = build_remediation_plan(
            {},
            findings=[],
            visibility_gaps=[],
            offline_control_analysis={},
            policy_analysis={},
            iam_analysis={},
            privacy_analysis={},
            evidence_guide={
                "top_missing_evidence": [
                    {
                        "id": "gap-custom",
                        "priority": "critical_gap",
                        "type": "identity_permissions_missing",
                        "target": "github",
                        "reason": "Permission export is missing.",
                        "requested_evidence": "GitHub app permission export.",
                    }
                ]
            },
        )

        self.assertEqual(plan["summary"]["actions"], 1)
        self.assertEqual(plan["actions"][0]["priority"], "P1")
        self.assertEqual(plan["actions"][0]["owner"], "unassigned")
        self.assertEqual(plan["actions"][0]["requested_evidence"], "GitHub app permission export.")


if __name__ == "__main__":
    unittest.main()
