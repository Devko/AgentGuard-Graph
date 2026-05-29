import contextlib
import io
import json
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import load_report
from agentguard_graph.cli import main
from agentguard_graph.portfolio import build_portfolio_report, load_portfolio_reports, render_portfolio_html, render_portfolio_markdown


class PortfolioTests(unittest.TestCase):
    def test_build_portfolio_report_rolls_up_persona_fields(self):
        support = load_report("support-agent")
        coding = load_report("coding-agent")
        support["findings"][0]["risk_status"] = "accepted"
        support["findings"][0]["accepted_risk"] = {
            "status": "accepted",
            "accepted": True,
            "expired": False,
            "id": "risk-support",
            "owner": "appsec",
            "reason": "Temporary exception.",
            "expires_at": "2999-12-31",
        }
        coding = deepcopy(coding)
        coding["findings"][0]["risk_status"] = "acceptance_expired"
        coding["findings"][0]["accepted_risk"] = {
            "status": "expired",
            "accepted": False,
            "expired": True,
            "id": "risk-coding",
            "owner": "appsec",
            "reason": "Expired exception.",
            "expires_at": "2000-01-01",
        }
        reports = [support, coding]

        portfolio = build_portfolio_report(reports, source="reports")

        self.assertEqual(portfolio["summary"]["reports"], 2)
        self.assertGreaterEqual(portfolio["summary"]["findings"], 2)
        self.assertGreaterEqual(portfolio["summary"]["high"], 1)
        owners = {row["key"]: row for row in portfolio["rollups"]["by_owner"]}
        self.assertIn("support-platform", owners)
        self.assertIn("developer-platform", owners)
        environments = {row["key"] for row in portfolio["rollups"]["by_environment"]}
        self.assertIn("production", environments)
        business_units = {row["key"] for row in portfolio["rollups"]["by_business_unit"]}
        self.assertIn("customer_support", business_units)
        self.assertIn("engineering", business_units)
        self.assertEqual(portfolio["summary"]["accepted_risk_findings"], 1)
        self.assertEqual(portfolio["summary"]["expired_accepted_risk_findings"], 1)
        self.assertEqual(portfolio["review"]["label"], "Expired accepted risk")
        risk_statuses = {row["key"] for row in portfolio["rollups"]["by_risk_status"]}
        self.assertIn("accepted", risk_statuses)
        self.assertIn("acceptance_expired", risk_statuses)
        path_states = {row["key"] for row in portfolio["rollups"]["by_path_state"]}
        self.assertIn("observed_allowed", path_states)
        self.assertTrue(portfolio["rollups"]["visibility_gaps_by_priority"])
        self.assertTrue(portfolio["top_findings"])
        self.assertTrue(portfolio["top_visibility_gaps"])

        markdown = render_portfolio_markdown(portfolio)
        self.assertIn("AgentGuard Graph Portfolio", markdown)
        self.assertIn("Owner Rollup", markdown)
        self.assertIn("Risk Status Rollup", markdown)
        self.assertIn("Expired accepted risk", markdown)
        self.assertIn("support-platform", markdown)

    def test_build_portfolio_report_rolls_up_manifest_and_remediation_status(self):
        current = deepcopy(load_report("support-agent"))
        old_report = deepcopy(load_report("coding-agent"))
        current["evidence_manifest"] = {
            "status": "present",
            "path": "agent-evidence/evidence-manifest.json",
            "summary": {
                "checked_count": 4,
                "changed_count": 2,
                "missing_count": 1,
                "unmanifested_count": 3,
            },
            "changed": [{"path": "identity.json", "fields": ["sha256"]}],
            "missing": [{"path": "events.jsonl"}],
            "unmanifested": [{"path": "approval-policy.json"}],
            "errors": ["example warning"],
        }
        del old_report["evidence_manifest"]
        del old_report["remediation_plan"]

        portfolio = build_portfolio_report([current, old_report], source="reports")

        self.assertEqual(portfolio["summary"]["reports_with_manifest_present"], 1)
        self.assertEqual(portfolio["summary"]["reports_with_manifest_not_provided"], 1)
        self.assertEqual(portfolio["summary"]["manifest_changed"], 2)
        self.assertEqual(portfolio["summary"]["manifest_missing"], 1)
        self.assertEqual(portfolio["summary"]["manifest_unmanifested"], 3)
        self.assertGreater(portfolio["summary"]["remediation_actions"], 0)
        self.assertGreaterEqual(portfolio["summary"]["remediation_p1"], 1)
        self.assertTrue(portfolio["rollups"]["evidence_manifest_by_status"])
        self.assertTrue(portfolio["rollups"]["remediation_by_owner"])
        self.assertTrue(portfolio["rollups"]["remediation_by_category"])
        self.assertTrue(portfolio["rollups"]["remediation_by_system"])
        self.assertTrue(portfolio["top_remediation_actions"])
        self.assertEqual(portfolio["reports"][1]["manifest_status"], "not_provided")
        self.assertEqual(portfolio["reports"][1]["remediation_actions"], 0)

        markdown = render_portfolio_markdown(portfolio)
        self.assertIn("Evidence Manifest Rollup", markdown)
        self.assertIn("Remediation Owner Rollup", markdown)
        self.assertIn("changed=2 missing=1 unmanifested=3", markdown)

    def test_portfolio_cli_writes_json_markdown_and_html(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            reports_dir = tmp_path / "reports"
            reports_dir.mkdir()
            (reports_dir / "support-risk.json").write_text(json.dumps(load_report("support-agent")), encoding="utf-8")
            nested = reports_dir / "nested"
            nested.mkdir()
            (nested / "coding-risk.json").write_text(json.dumps(load_report("coding-agent")), encoding="utf-8")
            (reports_dir / "not-a-report.json").write_text(json.dumps({"inventory": {}}), encoding="utf-8")
            out_path = tmp_path / "portfolio.json"
            markdown_path = tmp_path / "portfolio.md"
            html_path = tmp_path / "portfolio.html"

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    main(
                        [
                            "portfolio",
                            "--reports-dir",
                            str(reports_dir),
                            "--out",
                            str(out_path),
                            "--markdown",
                            str(markdown_path),
                            "--html",
                            str(html_path),
                        ]
                    ),
                    0,
                )

            self.assertIn("portfolio summary:", stdout.getvalue())
            self.assertIn("business_units=2", stdout.getvalue())
            report = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["reports"], 2)
            self.assertIn("by_owner", report["rollups"])
            self.assertIn("AgentGuard Graph Portfolio", markdown_path.read_text(encoding="utf-8"))
            html = html_path.read_text(encoding="utf-8")
            self.assertIn("AgentGuard Graph Portfolio", html)
            self.assertIn("portfolio summary", html)
            self.assertIn("support-platform", html)
            self.assertIn("Business Unit", html)
            self.assertIn("Evidence Manifest", html)
            self.assertIn("Remediation Owners", html)
            self.assertIn("Top Remediation Actions", html)
            self.assertIn('id="filter-owner"', html)
            self.assertIn('id="filter-business"', html)
            self.assertIn('id="filter-environment"', html)
            self.assertIn('id="filter-tier"', html)
            self.assertIn('id="filter-state"', html)
            self.assertIn('id="filter-risk"', html)
            self.assertIn('id="filter-gap-priority"', html)
            self.assertIn('id="filter-gap-type"', html)
            self.assertNotIn("https://", html)
            self.assertNotIn("http://", html)

    def test_portfolio_html_escapes_untrusted_strings_and_has_no_remote_assets(self):
        support = deepcopy(load_report("support-agent"))
        support["findings"][0]["title"] = '</script><img src=x onerror="alert(1)">'
        support["findings"][0]["operational_context"]["owner"] = '<script>alert("owner")</script>'
        support["visibility_gaps"][0]["reason"] = '<svg onload="alert(1)"></svg>'
        support["remediation_plan"]["actions"][0]["reason"] = '<img src=x onerror="alert(2)">'
        support["remediation_plan"]["actions"][0]["owner"] = '<script>alert("plan")</script>'

        portfolio = build_portfolio_report([support], source="reports")
        rendered = render_portfolio_html(portfolio)

        self.assertIn("&lt;/script&gt;&lt;img", rendered)
        self.assertIn("&lt;script&gt;alert(&quot;owner&quot;)&lt;/script&gt;", rendered)
        self.assertIn("&lt;svg onload=&quot;alert(1)&quot;&gt;&lt;/svg&gt;", rendered)
        self.assertIn("&lt;img src=x onerror=&quot;alert(2)&quot;&gt;", rendered)
        self.assertIn("&lt;script&gt;alert(&quot;plan&quot;)&lt;/script&gt;", rendered)
        self.assertNotIn('</script><img src=x onerror="alert(1)">', rendered)
        self.assertNotIn('<script>alert("owner")</script>', rendered)
        self.assertNotIn('<svg onload="alert(1)"></svg>', rendered)
        self.assertNotIn('<img src=x onerror="alert(2)">', rendered)
        self.assertNotIn('<script>alert("plan")</script>', rendered)
        self.assertIn("<style>", rendered)
        self.assertIn("<script>", rendered)
        self.assertNotIn("https://", rendered)
        self.assertNotIn("http://", rendered)

    def test_load_portfolio_reports_can_disable_recursive_scan(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            reports_dir = tmp_path / "reports"
            reports_dir.mkdir()
            nested = reports_dir / "nested"
            nested.mkdir()
            (nested / "coding-risk.json").write_text(json.dumps(load_report("coding-agent")), encoding="utf-8")

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(
                    main(
                        [
                            "portfolio",
                            "--reports-dir",
                            str(reports_dir),
                            "--out",
                            str(tmp_path / "portfolio.json"),
                            "--no-recursive",
                        ]
                    ),
                    2,
                )

            self.assertIn("no AgentGuard risk reports found", stderr.getvalue())

            reports = load_portfolio_reports(reports_dir)
            self.assertEqual(len(reports), 1)

    def test_portfolio_cli_rejects_directory_without_reports(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            reports_dir = tmp_path / "reports"
            reports_dir.mkdir()
            (reports_dir / "inventory.json").write_text(json.dumps({"inventory": {}}), encoding="utf-8")

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(
                    main(
                        [
                            "portfolio",
                            "--reports-dir",
                            str(reports_dir),
                            "--out",
                            str(tmp_path / "portfolio.json"),
                        ]
                    ),
                    2,
                )
            self.assertIn("no AgentGuard risk reports found", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
