import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import ROOT  # noqa: F401
from agentguard_graph.adapters.approval_policy import evaluate_policy, parse_approval_policy
from agentguard_graph.adapters.policy_evaluation import parse_cedar_policy, parse_opa_policy


class PolicyEvaluationAdapterTests(unittest.TestCase):
    def test_opa_decision_log_imports_concrete_rule(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "opa-decision-log.json"
            path.write_text(
                json.dumps(
                    {
                        "decision_id": "dec-1",
                        "path": "agentguard/allow",
                        "input": {
                            "agent": "support-agent",
                            "tool": "salesforce.get_contact",
                            "target_system": "salesforce",
                        },
                        "result": {"allow": True, "reason": "read-only CRM lookup"},
                    }
                ),
                encoding="utf-8",
            )

            parsed = parse_opa_policy(path)

            self.assertEqual(parsed["kind"], "opa_rego")
            self.assertEqual(parsed["policy_evaluations"][0]["decision"], "allow")
            rule = parsed["policies"][0]["rules"][0]
            self.assertEqual(rule["match"]["tool"], "salesforce.get_contact")
            self.assertEqual(rule["decision"], "allow")

    def test_rego_source_imports_static_match(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.rego"
            path.write_text(
                """
package agentguard

approval_required if {
  input.tool == "outlook.send_email"
  input.target_system == "microsoft_365"
  input.data_classes[_] == "customer_pii"
}
""",
                encoding="utf-8",
            )

            parsed = parse_opa_policy(path)
            rule = parsed["policies"][0]["rules"][0]

            self.assertEqual(rule["decision"], "approval_required")
            self.assertEqual(rule["match"]["tool"], "outlook.send_email")
            self.assertEqual(rule["match"]["data_classes_any"], ["customer_pii"])

    def test_rego_set_rule_imports_deny_match(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.rego"
            path.write_text(
                """
package agentguard

deny[msg] {
  input.tool == "github.delete_repo"
  input.target_system == "github"
  msg := "repository deletion blocked"
}
""",
                encoding="utf-8",
            )

            parsed = parse_opa_policy(path)
            rule = parsed["policies"][0]["rules"][0]

            self.assertEqual(rule["decision"], "deny")
            self.assertEqual(rule["match"]["tool"], "github.delete_repo")

    def test_cedar_source_imports_forbid_policy(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.cedar"
            path.write_text(
                """
forbid(
  principal == Agent::"release-agent",
  action == Action::"kubernetes.apply_manifest",
  resource
) when {
  context.environment == "production"
};
""",
                encoding="utf-8",
            )

            parsed = parse_cedar_policy(path)
            rule = parsed["policies"][0]["rules"][0]

            self.assertEqual(rule["decision"], "deny")
            self.assertEqual(rule["match"]["agent"], "release-agent")
            self.assertEqual(rule["match"]["tool"], "kubernetes.apply_manifest")
            self.assertEqual(rule["match"]["environment"], "production")

    def test_imported_policy_matches_existing_evaluator(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "approval-policy.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "policies": [
                            {
                                "id": "cedar:test",
                                "engine": "cedar",
                                "rules": [
                                    {
                                        "id": "cedar-deny",
                                        "match": {"tool": "github.delete_repo"},
                                        "decision": "deny",
                                        "policy_engine": "cedar",
                                        "evaluation_id": "eval-1",
                                    }
                                ],
                            }
                        ],
                        "policy_evaluations": [
                            {
                                "id": "eval-1",
                                "engine": "cedar",
                                "decision": "deny",
                                "match": {"tool": "github.delete_repo"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            parsed = parse_approval_policy(path)
            result = evaluate_policy(parsed["policies"], "cedar:test", {"tool": "github.delete_repo"})

            self.assertEqual(result["decision"], "deny")
            self.assertEqual(result["policy_engine"], "cedar")
            self.assertEqual(parsed["policy_evaluations"][0]["engine"], "cedar")


if __name__ == "__main__":
    unittest.main()
