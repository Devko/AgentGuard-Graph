import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import load_report
from agentguard_graph.outputs.markdown import render_markdown, write_markdown_report


def roadmap_item(index: int) -> dict:
    return {
        "id": f"roadmap-{index}",
        "priority": "P1",
        "category": "policy",
        "title": f"Roadmap item {index}",
        "reason": f"Reason {index}.",
        "affected_count": index,
        "evidence_needed": [f"Evidence {index}"],
        "acceptance_criteria": [f"Acceptance {index}"],
    }


class MarkdownOutputTests(unittest.TestCase):
    def test_markdown_report_content(self):
        markdown = render_markdown(load_report("support-agent"))
        self.assertIn("# AgentGuard Graph Report", markdown)
        self.assertIn("Review brief", markdown)
        self.assertIn("Owner-routed remediation plan", markdown)
        self.assertIn("Owner rollup:", markdown)
        self.assertIn("Priority actions:", markdown)
        self.assertIn("Policy evaluation evidence", markdown)
        self.assertIn("Evidence manifest attestation", markdown)
        self.assertIn("Status: not_provided", markdown)
        self.assertIn("Offline remediation roadmap", markdown)
        self.assertIn("Offline control coverage", markdown)
        self.assertIn("Evidence posture:", markdown)
        self.assertIn("Top actions:", markdown)
        self.assertIn("Top attack paths", markdown)
        self.assertIn("support-triage-agent", markdown)
        self.assertIn("Observation:", markdown)

    def test_markdown_writer(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "risk.md"
            write_markdown_report(load_report("support-agent"), path)
            self.assertIn("Visibility gaps", path.read_text(encoding="utf-8"))

    def test_markdown_empty_report_and_runtime_observations(self):
        empty = {
            "summary": {},
            "findings": [],
            "inventory": {"agents": [], "tools": [], "identities": []},
            "visibility_gaps": [],
            "graph": {"nodes": []},
        }
        rendered_empty = render_markdown(empty)
        self.assertIn("No attack-path findings", rendered_empty)
        self.assertIn("No visibility gaps", rendered_empty)

        report = load_report("support-agent")
        rendered = render_markdown(report)
        self.assertIn("Runtime observations", rendered)
        self.assertIn("agent.tool_call", rendered)
        self.assertIn("&lt;", render_markdown({"summary": {}, "findings": [{"title": "<x>", "tier": "low"}], "inventory": {}, "graph": {}}))

    def test_markdown_roadmap_shows_acceptance_criteria_and_overflow(self):
        report = {
            "summary": {},
            "offline_control_analysis": {
                "summary": {"roadmap_items": 13},
                "roadmap": [roadmap_item(index) for index in range(13)],
            },
            "findings": [],
            "inventory": {"agents": [], "tools": [], "identities": []},
            "visibility_gaps": [],
            "graph": {"nodes": []},
        }
        rendered = render_markdown(report)
        self.assertIn("Acceptance: Acceptance 0", rendered)
        self.assertIn("1 more offline remediation roadmap item not shown.", rendered)
        self.assertNotIn("Roadmap item 12", rendered)

    def test_markdown_policy_rule_risks_are_rendered(self):
        report = load_report("support-agent")
        report["policy_analysis"]["summary"]["policy_rule_risks"] = 1
        report["policy_analysis"]["summary"]["broad_allows"] = 1
        report["policy_analysis"]["summary"]["shadowed_rules"] = 0
        report["policy_analysis"]["summary"]["conflicting_decisions"] = 0
        report["policy_analysis"]["rule_risks"] = [
            {
                "type": "broad_allow_high_risk",
                "agent": "support-triage-agent",
                "tool": "shell.run",
                "effective_rule": "allow-risk-tag",
                "effective_decision": "allow",
                "matching_rules": [{"rule": "allow-risk-tag", "decision": "allow"}],
                "reason": "A broad allow rule is effective.",
                "repair": "Require approval for command execution.",
            }
        ]

        rendered = render_markdown(report)

        self.assertIn("Policy rule risks", rendered)
        self.assertIn("broad_allow_high_risk", rendered)
        self.assertIn("allow-risk-tag", rendered)

    def test_markdown_manifest_differences_are_rendered(self):
        report = load_report("support-agent")
        report["evidence_manifest"] = {
            "status": "present",
            "path": "evidence/evidence-manifest.json",
            "summary": {"checked_count": 5, "changed_count": 1, "missing_count": 1, "unmanifested_count": 1},
            "changed": [{"path": "agentguard.json", "fields": ["sha256", "size_bytes"]}],
            "missing": [{"path": "events.jsonl"}],
            "unmanifested": [{"path": "collector-summary.json"}],
            "errors": [],
        }

        rendered = render_markdown(report)

        self.assertIn("Changed files: 1", rendered)
        self.assertIn("changed: agentguard.json (sha256, size_bytes)", rendered)
        self.assertIn("missing: events.jsonl", rendered)
        self.assertIn("unmanifested: collector-summary.json", rendered)


if __name__ == "__main__":
    unittest.main()
