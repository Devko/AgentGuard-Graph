import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import load_report
from agentguard_graph.outputs.html import _edge_class, _node_class, _path_graph_from_finding, render_html, write_html_report


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


class HtmlOutputTests(unittest.TestCase):
    def test_html_escaping_with_hostile_strings(self):
        report = load_report("support-agent")
        report["findings"][0]["title"] = '<script>alert("x")</script>'
        report["findings"][0]["evidence"].append('<img src=x onerror="alert(1)">')
        rendered = render_html(report)
        self.assertIn("&lt;script&gt;alert", rendered)
        self.assertIn("&lt;img src=x", rendered)
        self.assertNotIn('<script>alert("x")</script>', rendered)
        self.assertNotIn("<img src=x", rendered)

    def test_html_writer_is_self_contained(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "risk.html"
            write_html_report(load_report("support-agent"), path)
            html = path.read_text(encoding="utf-8")
            self.assertIn("<style>", html)
            self.assertIn('<script type="application/json" id="report-findings">', html)
            self.assertIn('<script type="application/json" id="report-graph">', html)
            self.assertIn("selectFinding", html)
            self.assertIn('data-finding-id="finding-', html)
            self.assertIn("observed_allowed", html)
            self.assertIn("observed_blocked", html)
            self.assertIn("nodeById", html)
            self.assertIn("edgeById", html)
            self.assertNotIn("https://", html)
            self.assertNotIn("http://", html)

    def test_simple_html_adds_beginner_overview_and_hides_raw_scoring(self):
        rendered = render_html(load_report("support-agent"), simple=True)
        self.assertIn('class="simple-mode"', rendered)
        self.assertIn("Simple mode", rendered)
        self.assertIn('class="simple-overview"', rendered)
        self.assertIn("What matters", rendered)
        self.assertIn("Fix first", rendered)
        self.assertIn("Evidence to request", rendered)
        self.assertIn("Re-run without <code>--simple</code>", rendered)
        self.assertIn('class="detail-group advanced-only"', rendered)
        self.assertIn("advanced", rendered)
        self.assertNotIn('id="remediation-plan" class="secondary-panel" open', rendered)

    def test_html_has_professional_report_controls_and_next_evidence(self):
        rendered = render_html(load_report("support-agent"))
        for expected in [
            "Security operations report",
            "Agent risk, controls, and evidence gaps.",
            "--nav: #152033",
            "--accent-3: #7c3aed",
            "--shadow-panel",
            "metric::before",
            "border-top: 4px solid var(--accent)",
            'class="metrics"',
            'class="topline"',
            "Evidence posture",
            "Primary risk",
            "Top visibility gap",
            "<strong>Next:</strong>",
            "minmax(360px, 440px) minmax(540px, 1fr) minmax(370px, 460px)",
            "min-height: 180px",
            'class="filter-shell"',
            'class="detail-group"',
            ".node-input_source",
            'class="risk-view"',
            'aria-label="ranked risk list"',
            'class="path-panel"',
            'aria-label="selected attack path"',
            "Selected risk",
            'id="filter-search"',
            "Clear filters",
            "Attack Path Map",
            "Visibility Gaps",
            "Next Evidence To Request",
            "Source Files",
            "Owner-Routed Remediation Plan",
            "Owner rollup",
            "Priority actions",
            "Policy Evaluation Evidence",
            "Evidence Manifest Attestation",
            "not provided",
            "Offline remediation roadmap",
            "Control coverage",
            "Data And Privacy Evidence",
            "Employee data",
            "Credentials",
            "Payment data",
            "Regulated records",
            "Filters search evidence",
            "No findings match the current filters",
        ]:
            self.assertIn(expected, rendered)

    def test_html_keeps_primary_risk_surface_before_secondary_sections(self):
        rendered = render_html(load_report("demo-enterprise"))
        layout_index = rendered.index('<div class="layout">')
        risk_queue_index = rendered.index("Risk Queue")
        guide_index = rendered.index('id="evidence-guide"')
        runtime_index = rendered.index('id="runtime-reconstruction"')
        self.assertLess(layout_index, guide_index)
        self.assertLess(risk_queue_index, guide_index)
        self.assertLess(risk_queue_index, runtime_index)
        self.assertNotIn('class="guide-panel"', rendered)
        self.assertIn('class="secondary-panel"', rendered)

    def test_embedded_json_escapes_script_breakout(self):
        report = load_report("support-agent")
        report["findings"][0]["title"] = "</script><script>alert(1)</script>"
        rendered = render_html(report)
        self.assertIn("\\u003c/script\\u003e", rendered)
        self.assertNotIn("</script><script>alert(1)</script>", rendered)

    def test_html_handles_empty_and_large_reports(self):
        report = {
            "summary": {"agents": 0, "tools": 0, "urgent": 0, "high": 0, "visibility_gaps": 0},
            "inventory": {"agents": []},
            "graph": {"nodes": [], "edges": []},
            "findings": [],
        }
        rendered = render_html(report)
        self.assertIn("No findings produced.", rendered)
        self.assertIn("No selected attack path", rendered)

        large = load_report("support-agent")
        large["findings"][0]["evidence"].append("x" * 30000)
        rendered_large = render_html(large)
        self.assertIn("... truncated ...", rendered_large)

    def test_path_graph_uses_metadata_classes_and_supporting_edges(self):
        graph = {
            "nodes": [
                {
                    "id": "input:i",
                    "type": "input_source",
                    "label": "Input",
                    "confidence": "high",
                    "evidence_layer": "agent_config",
                    "visibility_gaps": [],
                },
                {
                    "id": "agent:a",
                    "type": "agent",
                    "label": "Agent",
                    "confidence": "high",
                    "evidence_layer": "agent_config",
                    "visibility_gaps": [],
                },
                {
                    "id": "approval_policy:p",
                    "type": "approval_policy",
                    "label": "Policy",
                    "confidence": "low",
                    "evidence_layer": "inferred_gap",
                    "visibility_gaps": ["gap-approval"],
                },
            ],
            "edges": [
                {
                    "id": "agent_receives_input:input_i->agent_a",
                    "from_node": "input:i",
                    "to_node": "agent:a",
                    "type": "agent_receives_input",
                    "label": "receives input",
                    "confidence": "low",
                    "evidence_layer": "agent_config",
                },
                {
                    "id": "approval_present:agent_a->approval_policy_p",
                    "from_node": "input:i",
                    "to_node": "approval_policy:p",
                    "type": "approval_present",
                    "label": "approval required",
                    "confidence": "high",
                    "evidence_layer": "policy",
                },
            ],
        }
        finding = {
            "nodes": ["input:i", "agent:a", "approval_policy:p"],
            "edges": ["agent_receives_input:input_i->agent_a", "approval_present:agent_a->approval_policy_p"],
        }
        rendered = _path_graph_from_finding(finding, graph)
        self.assertIn("low-confidence", rendered)
        self.assertIn("approval-node", rendered)
        self.assertIn("Supporting graph edges", rendered)
        self.assertIn("blocked-edge", _edge_class({"type": "event_blocked"}))
        self.assertIn("observed-edge", _edge_class({"type": "event_allowed"}))
        self.assertIn("unknown", _node_class({"type": "unknown"}))

    def test_html_roadmap_shows_acceptance_criteria_and_overflow(self):
        report = {
            "summary": {},
            "inventory": {"agents": []},
            "graph": {"nodes": [], "edges": []},
            "findings": [],
            "offline_control_analysis": {
                "summary": {"roadmap_items": 17},
                "roadmap": [roadmap_item(index) for index in range(17)],
            },
        }
        rendered = render_html(report)
        roadmap_section = rendered.split("<h3>Offline remediation roadmap</h3>", 1)[1].split("</ul>", 1)[0]
        self.assertIn("Acceptance: Acceptance 0", rendered)
        self.assertIn("1 more offline remediation roadmap item not shown.", roadmap_section)
        self.assertNotIn("Roadmap item 16", roadmap_section)

    def test_html_policy_rule_risks_are_rendered(self):
        report = load_report("support-agent")
        report["policy_analysis"]["summary"]["policy_rule_risks"] = 1
        report["policy_analysis"]["rule_risks"] = [
            {
                "type": "broad_allow_high_risk",
                "agent": "support-triage-agent",
                "tool": "shell.run",
                "effective_rule": "allow-risk-tag",
                "effective_decision": "allow",
                "reason": "A broad allow rule is effective.",
                "repair": "Require approval for command execution.",
            }
        ]

        rendered = render_html(report)

        self.assertIn("Policy rule risks", rendered)
        self.assertIn("broad_allow_high_risk", rendered)
        self.assertIn("allow-risk-tag", rendered)

    def test_html_manifest_differences_are_rendered(self):
        report = load_report("support-agent")
        report["evidence_manifest"] = {
            "status": "present",
            "path": "evidence/evidence-manifest.json",
            "summary": {"checked_count": 5, "changed_count": 1, "missing_count": 1, "unmanifested_count": 1},
            "changed": [{"path": "agentguard.json", "fields": ["sha256"]}],
            "missing": [{"path": "events.jsonl"}],
            "unmanifested": [{"path": "collector-summary.json"}],
            "errors": [],
        }

        rendered = render_html(report)

        self.assertIn("Evidence Manifest Attestation", rendered)
        self.assertIn("changed: agentguard.json (sha256)", rendered)
        self.assertIn("missing: events.jsonl", rendered)
        self.assertIn("unmanifested: collector-summary.json", rendered)


if __name__ == "__main__":
    unittest.main()
