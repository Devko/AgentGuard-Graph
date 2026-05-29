"""Portfolio rollup helpers for saved AgentGuard reports."""

from __future__ import annotations

import json
import html
from pathlib import Path
from typing import Any

from . import __version__
from .errors import EvidenceLoadError


TIER_ORDER = {"urgent": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "unknown": 5}
GAP_ORDER = {"critical_gap": 0, "high_gap": 1, "medium_gap": 2, "low_gap": 3, "unknown": 4}
RISK_STATUS_ORDER = {"acceptance_expired": 0, "open": 1, "accepted": 2}


def load_portfolio_reports(reports_dir: str | Path, *, recursive: bool = True) -> list[dict[str, Any]]:
    root = Path(reports_dir)
    if not root.exists():
        raise EvidenceLoadError(f"{root}: reports directory not found")
    if not root.is_dir():
        raise EvidenceLoadError(f"{root}: reports path must be a directory")
    pattern = "**/*.json" if recursive else "*.json"
    reports: list[dict[str, Any]] = []
    for path in sorted(root.glob(pattern)):
        if not path.is_file():
            continue
        report = _read_report_if_valid(path)
        if report:
            reports.append(report)
    if not reports:
        raise EvidenceLoadError(f"{root}: no AgentGuard risk reports found")
    return reports


def build_portfolio_report(reports: list[dict[str, Any]], *, source: str = "") -> dict[str, Any]:
    report_entries = [_report_entry(report) for report in reports]
    all_findings = [
        _finding_entry(report, finding)
        for report in reports
        for finding in report.get("findings", [])
        if isinstance(finding, dict)
    ]
    all_gaps = [
        _gap_entry(report, gap)
        for report in reports
        for gap in report.get("visibility_gaps", [])
        if isinstance(gap, dict)
    ]
    manifest_entries = [_manifest_entry(report) for report in reports]
    remediation_actions = [
        _remediation_action_entry(report, action)
        for report in reports
        for action in ((report.get("remediation_plan") or {}).get("actions", []) if isinstance(report.get("remediation_plan"), dict) else [])
        if isinstance(action, dict)
    ]
    manifest_status_counts = _count_values(manifest_entries, "status")
    summary = {
        "reports": len(reports),
        "agents": sum(_int((report.get("summary") or {}).get("agents", 0)) for report in reports),
        "findings": len(all_findings),
        "attack_paths": sum(len(report.get("attack_paths", [])) for report in reports),
        "visibility_gaps": len(all_gaps),
        "urgent": sum(1 for finding in all_findings if finding["tier"] == "urgent"),
        "high": sum(1 for finding in all_findings if finding["tier"] == "high"),
        "medium": sum(1 for finding in all_findings if finding["tier"] == "medium"),
        "low": sum(1 for finding in all_findings if finding["tier"] == "low"),
        "informational": sum(1 for finding in all_findings if finding["tier"] == "informational"),
        "owners": len({finding["owner"] for finding in all_findings if finding["owner"] != "unknown"}),
        "environments": len({finding["environment"] for finding in all_findings if finding["environment"] != "unknown"}),
        "business_units": len({finding["business_unit"] for finding in all_findings if finding["business_unit"] != "unknown"}),
        "critical_gaps": sum(1 for gap in all_gaps if gap["priority"] == "critical_gap"),
        "high_gaps": sum(1 for gap in all_gaps if gap["priority"] == "high_gap"),
        "open_findings": sum(1 for finding in all_findings if finding["risk_status"] == "open"),
        "accepted_risk_findings": sum(1 for finding in all_findings if finding["risk_status"] == "accepted"),
        "expired_accepted_risk_findings": sum(
            1 for finding in all_findings if finding["risk_status"] == "acceptance_expired"
        ),
        "reports_with_manifest_present": manifest_status_counts.get("present", 0),
        "reports_with_manifest_missing": manifest_status_counts.get("missing", 0),
        "reports_with_manifest_not_provided": manifest_status_counts.get("not_provided", 0),
        "manifest_changed": sum(item["changed_count"] for item in manifest_entries),
        "manifest_missing": sum(item["missing_count"] for item in manifest_entries),
        "manifest_unmanifested": sum(item["unmanifested_count"] for item in manifest_entries),
        "remediation_actions": len(remediation_actions),
        "remediation_p1": sum(1 for action in remediation_actions if action["priority"] == "P1"),
        "remediation_p2": sum(1 for action in remediation_actions if action["priority"] == "P2"),
        "remediation_p3": sum(1 for action in remediation_actions if action["priority"] == "P3"),
        "remediation_owners": len({action["owner"] for action in remediation_actions if action["owner"] != "unassigned"}),
        "remediation_systems": len({action["target"] for action in remediation_actions if action["target"] != "unknown"}),
        "remediation_categories": len({action["category"] for action in remediation_actions if action["category"] != "unknown"}),
    }
    return {
        "schema_version": "0.1",
        "tool": {"name": "agentguard-graph", "version": __version__},
        "portfolio": {
            "source": source,
            "report_count": len(reports),
        },
        "summary": summary,
        "review": _portfolio_review(summary, all_findings, all_gaps),
        "reports": report_entries,
        "rollups": {
            "by_owner": _rollup(all_findings, "owner"),
            "by_environment": _rollup(all_findings, "environment"),
            "by_business_unit": _rollup(all_findings, "business_unit"),
            "by_tier": _rollup(all_findings, "tier", rank=TIER_ORDER),
            "by_path_state": _rollup(all_findings, "path_state"),
            "by_risk_status": _rollup(all_findings, "risk_status"),
            "visibility_gaps_by_priority": _gap_rollup(all_gaps, "priority", rank=GAP_ORDER),
            "visibility_gaps_by_type": _gap_rollup(all_gaps, "type"),
            "evidence_manifest_by_status": _manifest_status_rollup(manifest_entries),
            "remediation_by_owner": _remediation_rollup(remediation_actions, "owner"),
            "remediation_by_category": _remediation_rollup(remediation_actions, "category"),
            "remediation_by_system": _remediation_rollup(remediation_actions, "target"),
        },
        "top_findings": _top_findings(all_findings),
        "top_visibility_gaps": _top_gaps(all_gaps),
        "top_remediation_actions": _top_remediation_actions(remediation_actions),
    }


def write_portfolio_markdown(portfolio_report: dict[str, Any], path: str | Path) -> None:
    output_path = Path(path)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(render_portfolio_markdown(portfolio_report), encoding="utf-8")
    except OSError as exc:
        raise EvidenceLoadError(f"{output_path}: cannot write Markdown portfolio report: {exc}") from exc


def write_portfolio_html(portfolio_report: dict[str, Any], path: str | Path) -> None:
    output_path = Path(path)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(render_portfolio_html(portfolio_report), encoding="utf-8")
    except OSError as exc:
        raise EvidenceLoadError(f"{output_path}: cannot write HTML portfolio report: {exc}") from exc


def render_portfolio_markdown(portfolio_report: dict[str, Any]) -> str:
    summary = portfolio_report.get("summary", {})
    review = portfolio_report.get("review", {})
    lines = [
        "# AgentGuard Graph Portfolio",
        "",
        f"- Reports: {summary.get('reports', 0)}",
        f"- Findings: {summary.get('findings', 0)}",
        f"- Urgent / high: {summary.get('urgent', 0)} / {summary.get('high', 0)}",
        f"- Visibility gaps: {summary.get('visibility_gaps', 0)}",
        f"- Accepted risk: {summary.get('accepted_risk_findings', 0)}",
        f"- Expired accepted risk: {summary.get('expired_accepted_risk_findings', 0)}",
        (
            "- Evidence manifests: "
            f"present={summary.get('reports_with_manifest_present', 0)} "
            f"missing={summary.get('reports_with_manifest_missing', 0)} "
            f"not_provided={summary.get('reports_with_manifest_not_provided', 0)}"
        ),
        (
            "- Manifest drift: "
            f"changed={summary.get('manifest_changed', 0)} "
            f"missing={summary.get('manifest_missing', 0)} "
            f"unmanifested={summary.get('manifest_unmanifested', 0)}"
        ),
        (
            "- Remediation actions: "
            f"{summary.get('remediation_actions', 0)} "
            f"(P1={summary.get('remediation_p1', 0)}, "
            f"P2={summary.get('remediation_p2', 0)}, "
            f"P3={summary.get('remediation_p3', 0)})"
        ),
        f"- Decision: {_md(str(review.get('decision', 'unknown')))}",
        f"- Label: {_md(str(review.get('label', '')))}",
        "",
        "## Required Actions",
        "",
    ]
    for action in review.get("required_actions", []) or ["No required actions."]:
        lines.append(f"- {_md(str(action))}")
    lines.extend(["", "## Owner Rollup", ""])
    _append_rollup_table(lines, portfolio_report.get("rollups", {}).get("by_owner", []))
    lines.extend(["", "## Environment Rollup", ""])
    _append_rollup_table(lines, portfolio_report.get("rollups", {}).get("by_environment", []))
    lines.extend(["", "## Business Unit Rollup", ""])
    _append_rollup_table(lines, portfolio_report.get("rollups", {}).get("by_business_unit", []))
    lines.extend(["", "## Risk Status Rollup", ""])
    _append_rollup_table(lines, portfolio_report.get("rollups", {}).get("by_risk_status", []))
    lines.extend(["", "## Evidence Manifest Rollup", ""])
    _append_manifest_table(lines, portfolio_report.get("rollups", {}).get("evidence_manifest_by_status", []))
    lines.extend(["", "## Remediation Owner Rollup", ""])
    _append_remediation_table(lines, portfolio_report.get("rollups", {}).get("remediation_by_owner", []))
    lines.extend(["", "## Remediation Category Rollup", ""])
    _append_remediation_table(lines, portfolio_report.get("rollups", {}).get("remediation_by_category", []))
    lines.extend(["", "## Remediation System Rollup", ""])
    _append_remediation_table(lines, portfolio_report.get("rollups", {}).get("remediation_by_system", []))
    lines.extend(["", "## Top Findings", ""])
    top_findings = portfolio_report.get("top_findings", [])
    if not top_findings:
        lines.append("None.")
    for finding in top_findings:
        lines.append(
            f"- `{_md(str(finding.get('id', '')))}` "
            f"{_md(str(finding.get('tier', 'unknown')))} "
            f"score={finding.get('score', 0)} "
            f"risk_status={_md(str(finding.get('risk_status', 'open')))} "
            f"owner={_md(str(finding.get('owner', 'unknown')))} "
            f"report={_md(str(finding.get('report_label', '')))}: "
            f"{_md(str(finding.get('title', '')))}"
        )
    lines.extend(["", "## Top Visibility Gaps", ""])
    top_gaps = portfolio_report.get("top_visibility_gaps", [])
    if not top_gaps:
        lines.append("None.")
    for gap in top_gaps:
        lines.append(
            f"- `{_md(str(gap.get('id', '')))}` "
            f"{_md(str(gap.get('priority', 'unknown')))} "
            f"{_md(str(gap.get('target', '')))}: {_md(str(gap.get('reason', '')))}"
        )
    lines.extend(["", "## Top Remediation Actions", ""])
    top_actions = portfolio_report.get("top_remediation_actions", [])
    if not top_actions:
        lines.append("None.")
    for action in top_actions:
        lines.append(
            f"- `{_md(str(action.get('id', '')))}` "
            f"{_md(str(action.get('priority', 'P2')))} "
            f"owner={_md(str(action.get('owner', 'unassigned')))} "
            f"category={_md(str(action.get('category', 'unknown')))} "
            f"target={_md(str(action.get('target', 'unknown')))} "
            f"report={_md(str(action.get('report_label', '')))}: "
            f"{_md(str(action.get('reason', '')))}"
        )
    lines.append("")
    return "\n".join(lines)


def render_portfolio_html(portfolio_report: dict[str, Any]) -> str:
    summary = portfolio_report.get("summary", {})
    review = portfolio_report.get("review", {})
    rollups = portfolio_report.get("rollups", {})
    findings = portfolio_report.get("top_findings", [])
    gaps = portfolio_report.get("top_visibility_gaps", [])
    remediation_actions = portfolio_report.get("top_remediation_actions", [])
    required_actions = review.get("required_actions", []) or ["No required actions."]
    filter_options = {
        "owner": _unique_values(findings, "owner"),
        "business_unit": _unique_values(findings, "business_unit"),
        "environment": _unique_values(findings, "environment"),
        "tier": _unique_values(findings, "tier", rank=TIER_ORDER),
        "path_state": _unique_values(findings, "path_state"),
        "risk_status": _unique_values(findings, "risk_status", rank=RISK_STATUS_ORDER),
        "gap_priority": _unique_values(gaps, "priority", rank=GAP_ORDER),
        "gap_type": _unique_values(gaps, "type"),
    }
    finding_cards = "".join(_portfolio_finding_card(finding) for finding in findings)
    if not finding_cards:
        finding_cards = '<div class="empty portfolio-item">No top findings.</div>'
    gap_cards = "".join(_portfolio_gap_card(gap) for gap in gaps)
    if not gap_cards:
        gap_cards = '<div class="empty portfolio-item">No top visibility gaps.</div>'
    actions = "".join(f"<li>{_html(action)}</li>" for action in required_actions)
    report_rows = _portfolio_report_rows(portfolio_report.get("reports", []))
    remediation_cards = "".join(_portfolio_remediation_card(action) for action in remediation_actions)
    if not remediation_cards:
        remediation_cards = '<div class="empty portfolio-item">No remediation actions.</div>'
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentGuard Graph Portfolio</title>
<style>
:root {{
  color-scheme: light;
  --bg: #f7f8fb;
  --panel: #ffffff;
  --ink: #172033;
  --muted: #5b6577;
  --line: #d9dee8;
  --accent: #176b87;
  --accent-2: #7a4d00;
  --danger: #b42318;
  --warn: #b54708;
  --ok: #067647;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--bg); color: var(--ink); font-family: Arial, Helvetica, sans-serif; line-height: 1.45; }}
header {{ background: #172033; color: #fff; padding: 28px clamp(18px, 4vw, 48px); }}
header p {{ margin: 6px 0 0; color: #d8e0ef; }}
main {{ padding: 22px clamp(14px, 3vw, 36px) 36px; }}
h1, h2, h3 {{ margin: 0; letter-spacing: 0; }}
h2 {{ font-size: 1.15rem; margin-bottom: 12px; }}
h3 {{ font-size: 1rem; margin-bottom: 8px; }}
.metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin-bottom: 18px; }}
.metric, .panel, .portfolio-item {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; box-shadow: 0 1px 2px rgba(17, 24, 39, .04); }}
.metric {{ padding: 14px; border-top: 4px solid var(--accent); }}
.metric strong {{ display: block; font-size: 1.55rem; }}
.metric span, .muted {{ color: var(--muted); font-size: .9rem; }}
.grid {{ display: grid; grid-template-columns: minmax(260px, 340px) minmax(0, 1fr); gap: 16px; align-items: start; }}
.panel {{ padding: 16px; margin-bottom: 16px; }}
.filters {{ display: grid; gap: 10px; }}
label {{ display: grid; gap: 4px; color: var(--muted); font-size: .84rem; }}
select, input {{ width: 100%; padding: 8px 10px; border: 1px solid var(--line); border-radius: 6px; background: #fff; color: var(--ink); }}
button {{ border: 1px solid var(--line); border-radius: 6px; background: #fff; color: var(--ink); padding: 8px 10px; cursor: pointer; }}
button:hover {{ border-color: var(--accent); }}
.rollups {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }}
table {{ width: 100%; border-collapse: collapse; font-size: .9rem; }}
th, td {{ padding: 7px 6px; border-bottom: 1px solid var(--line); text-align: right; }}
th:first-child, td:first-child {{ text-align: left; }}
.items {{ display: grid; gap: 10px; }}
.portfolio-item {{ padding: 14px; }}
.item-head {{ display: flex; justify-content: space-between; gap: 10px; align-items: start; }}
.item-head strong {{ font-size: 1rem; }}
.badges {{ display: flex; flex-wrap: wrap; gap: 6px; margin: 9px 0; }}
.badge {{ display: inline-flex; align-items: center; min-height: 24px; padding: 2px 8px; border-radius: 999px; background: #eef2f7; color: #283548; font-size: .78rem; }}
.tier-urgent, .tier-high, .gap-critical_gap, .risk-acceptance_expired {{ background: #fee4e2; color: var(--danger); }}
.tier-medium, .gap-high_gap {{ background: #fef0c7; color: var(--warn); }}
.tier-P1 {{ background: #fee4e2; color: var(--danger); }}
.tier-P2 {{ background: #fef0c7; color: var(--warn); }}
.tier-P3 {{ background: #dcfae6; color: var(--ok); }}
.risk-accepted {{ background: #dcfae6; color: var(--ok); }}
.meta {{ color: var(--muted); font-size: .88rem; display: flex; flex-wrap: wrap; gap: 8px 14px; }}
.empty {{ color: var(--muted); }}
.hidden {{ display: none; }}
@media (max-width: 860px) {{
  .grid {{ grid-template-columns: 1fr; }}
  header {{ padding-top: 22px; }}
}}
</style>
</head>
<body>
<header>
  <h1>AgentGuard Graph Portfolio</h1>
  <p>{_html(review.get("label", "Portfolio review"))}: {_html(review.get("reason", ""))}</p>
</header>
<main>
  <section class="metrics" aria-label="portfolio summary">
    {_metric_html("Reports", summary.get("reports", 0))}
    {_metric_html("Findings", summary.get("findings", 0))}
    {_metric_html("Urgent", summary.get("urgent", 0))}
    {_metric_html("High", summary.get("high", 0))}
    {_metric_html("Visibility gaps", summary.get("visibility_gaps", 0))}
    {_metric_html("Accepted risk", summary.get("accepted_risk_findings", 0))}
    {_metric_html("Expired accepted risk", summary.get("expired_accepted_risk_findings", 0))}
    {_metric_html("Owners", summary.get("owners", 0))}
    {_metric_html("Manifests present", summary.get("reports_with_manifest_present", 0))}
    {_metric_html("Manifest drift", summary.get("manifest_changed", 0) + summary.get("manifest_missing", 0) + summary.get("manifest_unmanifested", 0))}
    {_metric_html("Remediation actions", summary.get("remediation_actions", 0))}
    {_metric_html("P1 actions", summary.get("remediation_p1", 0))}
  </section>
  <div class="grid">
    <aside>
      <section class="panel">
        <h2>Filters</h2>
        <div class="filters">
          <label>Search<input id="filter-search" type="search" autocomplete="off"></label>
          {_select_html("owner", "Owner", filter_options["owner"])}
          {_select_html("business", "Business unit", filter_options["business_unit"])}
          {_select_html("environment", "Environment", filter_options["environment"])}
          {_select_html("tier", "Severity / tier", filter_options["tier"])}
          {_select_html("state", "Path state", filter_options["path_state"])}
          {_select_html("risk", "Risk status", filter_options["risk_status"])}
          {_select_html("gap-priority", "Gap priority", filter_options["gap_priority"])}
          {_select_html("gap-type", "Gap type", filter_options["gap_type"])}
          <button id="clear-filters" type="button">Clear filters</button>
          <div class="muted"><span id="match-count">{_html(len(findings) + len(gaps))}</span> matching items</div>
        </div>
      </section>
      <section class="panel">
        <h2>Required Actions</h2>
        <ul>{actions}</ul>
      </section>
    </aside>
    <div>
      <section class="panel">
        <h2>Rollups</h2>
        <div class="rollups">
          {_rollup_table_html("Owner", rollups.get("by_owner", []))}
          {_rollup_table_html("Business Unit", rollups.get("by_business_unit", []))}
          {_rollup_table_html("Environment", rollups.get("by_environment", []))}
          {_rollup_table_html("Severity", rollups.get("by_tier", []))}
          {_rollup_table_html("Path State", rollups.get("by_path_state", []))}
          {_rollup_table_html("Risk Status", rollups.get("by_risk_status", []))}
          {_gap_rollup_table_html("Gap Priority", rollups.get("visibility_gaps_by_priority", []))}
          {_gap_rollup_table_html("Gap Type", rollups.get("visibility_gaps_by_type", []))}
          {_manifest_rollup_table_html("Evidence Manifest", rollups.get("evidence_manifest_by_status", []))}
          {_remediation_rollup_table_html("Remediation Owners", rollups.get("remediation_by_owner", []))}
          {_remediation_rollup_table_html("Remediation Categories", rollups.get("remediation_by_category", []))}
          {_remediation_rollup_table_html("Remediation Systems", rollups.get("remediation_by_system", []))}
        </div>
      </section>
      <section class="panel">
        <h2>Reports</h2>
        {report_rows}
      </section>
      <section class="panel">
        <h2>Top Findings</h2>
        <div class="items" id="findings-list">{finding_cards}</div>
      </section>
      <section class="panel">
        <h2>Top Visibility Gaps</h2>
        <div class="items" id="gaps-list">{gap_cards}</div>
      </section>
      <section class="panel">
        <h2>Top Remediation Actions</h2>
        <div class="items" id="remediation-list">{remediation_cards}</div>
      </section>
      <div id="filtered-empty" class="panel empty hidden">No portfolio items match the current filters.</div>
    </div>
  </div>
</main>
<script>
(() => {{
  const controls = {{
    owner: document.getElementById("filter-owner"),
    business: document.getElementById("filter-business"),
    environment: document.getElementById("filter-environment"),
    tier: document.getElementById("filter-tier"),
    state: document.getElementById("filter-state"),
    risk: document.getElementById("filter-risk"),
    gapPriority: document.getElementById("filter-gap-priority"),
    gapType: document.getElementById("filter-gap-type"),
    search: document.getElementById("filter-search")
  }};
  const items = Array.from(document.querySelectorAll(".portfolio-item[data-kind]"));
  const matchCount = document.getElementById("match-count");
  const empty = document.getElementById("filtered-empty");
  function matches(item, key, value) {{
    return !value || (item.dataset[key] || "") === value;
  }}
  function applyFilters() {{
    const query = controls.search.value.trim().toLowerCase();
    let count = 0;
    for (const item of items) {{
      const visible =
        (!query || (item.dataset.search || "").includes(query)) &&
        matches(item, "owner", controls.owner.value) &&
        matches(item, "business", controls.business.value) &&
        matches(item, "environment", controls.environment.value) &&
        matches(item, "tier", controls.tier.value) &&
        matches(item, "state", controls.state.value) &&
        matches(item, "risk", controls.risk.value) &&
        matches(item, "gapPriority", controls.gapPriority.value) &&
        matches(item, "gapType", controls.gapType.value);
      item.hidden = !visible;
      if (visible) count += 1;
    }}
    matchCount.textContent = String(count);
    empty.classList.toggle("hidden", count !== 0);
  }}
  for (const control of Object.values(controls)) {{
    control.addEventListener(control.tagName === "INPUT" ? "input" : "change", applyFilters);
  }}
  document.getElementById("clear-filters").addEventListener("click", () => {{
    for (const control of Object.values(controls)) {{
      control.value = "";
    }}
    applyFilters();
  }});
}})();
</script>
</body>
</html>
"""


def _append_rollup_table(lines: list[str], rows: list[dict[str, Any]]) -> None:
    if not rows:
        lines.append("None.")
        return
    lines.extend(
        [
            "| Key | Findings | Urgent | High | Accepted | Expired | Gaps | Reports |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in rows[:12]:
        lines.append(
            f"| {_md(str(row.get('key', 'unknown')))} "
            f"| {row.get('findings', 0)} "
            f"| {row.get('urgent', 0)} "
            f"| {row.get('high', 0)} "
            f"| {row.get('accepted_risk', 0)} "
            f"| {row.get('expired_accepted_risk', 0)} "
            f"| {row.get('visibility_gaps', 0)} "
            f"| {row.get('reports', 0)} |"
        )


def _append_manifest_table(lines: list[str], rows: list[dict[str, Any]]) -> None:
    if not rows:
        lines.append("None.")
        return
    lines.extend(
        [
            "| Status | Reports | Changed | Missing | Unmanifested | Errors |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in rows:
        lines.append(
            f"| {_md(str(row.get('key', 'not_provided')))} "
            f"| {row.get('reports', 0)} "
            f"| {row.get('changed', 0)} "
            f"| {row.get('missing', 0)} "
            f"| {row.get('unmanifested', 0)} "
            f"| {row.get('errors', 0)} |"
        )


def _append_remediation_table(lines: list[str], rows: list[dict[str, Any]]) -> None:
    if not rows:
        lines.append("None.")
        return
    lines.extend(
        [
            "| Key | Actions | P1 | P2 | P3 | Reports |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in rows[:12]:
        lines.append(
            f"| {_md(str(row.get('key', 'unknown')))} "
            f"| {row.get('actions', 0)} "
            f"| {row.get('p1', 0)} "
            f"| {row.get('p2', 0)} "
            f"| {row.get('p3', 0)} "
            f"| {row.get('reports', 0)} |"
        )


def _portfolio_finding_card(finding: dict[str, Any]) -> str:
    search = _search_text(
        [
            finding.get("id", ""),
            finding.get("title", ""),
            finding.get("tier", ""),
            finding.get("path_state", ""),
            finding.get("risk_status", ""),
            finding.get("owner", ""),
            finding.get("business_unit", ""),
            finding.get("environment", ""),
            finding.get("report_label", ""),
        ]
    )
    return (
        '<article class="portfolio-item" data-kind="finding" '
        f'data-owner="{_attr_value(finding.get("owner", ""))}" '
        f'data-business="{_attr_value(finding.get("business_unit", ""))}" '
        f'data-environment="{_attr_value(finding.get("environment", ""))}" '
        f'data-tier="{_attr_value(finding.get("tier", ""))}" '
        f'data-state="{_attr_value(finding.get("path_state", ""))}" '
        f'data-risk="{_attr_value(finding.get("risk_status", ""))}" '
        'data-gap-priority="" data-gap-type="" '
        f'data-search="{_html_attr(search)}">'
        '<div class="item-head">'
        f'<strong>{_html(finding.get("title", ""))}</strong>'
        f'<span class="badge tier-{_html_attr(finding.get("tier", "unknown"))}">{_html(finding.get("tier", "unknown"))}</span>'
        "</div>"
        '<div class="badges">'
        f'<span class="badge">score {_html(finding.get("score", 0))}</span>'
        f'<span class="badge">{_html(finding.get("path_state", "unknown"))}</span>'
        f'<span class="badge risk-{_html_attr(finding.get("risk_status", "open"))}">{_html(finding.get("risk_status", "open"))}</span>'
        "</div>"
        '<div class="meta">'
        f'<span>id {_html(finding.get("id", ""))}</span>'
        f'<span>owner {_html(finding.get("owner", "unknown"))}</span>'
        f'<span>business unit {_html(finding.get("business_unit", "unknown"))}</span>'
        f'<span>environment {_html(finding.get("environment", "unknown"))}</span>'
        f'<span>report {_html(finding.get("report_label", ""))}</span>'
        "</div>"
        "</article>"
    )


def _portfolio_gap_card(gap: dict[str, Any]) -> str:
    search = _search_text(
        [
            gap.get("id", ""),
            gap.get("priority", ""),
            gap.get("type", ""),
            gap.get("target", ""),
            gap.get("reason", ""),
            gap.get("requested_evidence", ""),
            gap.get("report_label", ""),
        ]
    )
    return (
        '<article class="portfolio-item" data-kind="gap" '
        'data-owner="" data-business="" data-environment="" data-tier="" data-state="" data-risk="" '
        f'data-gap-priority="{_attr_value(gap.get("priority", ""))}" '
        f'data-gap-type="{_attr_value(gap.get("type", ""))}" '
        f'data-search="{_html_attr(search)}">'
        '<div class="item-head">'
        f'<strong>{_html(gap.get("target", ""))}</strong>'
        f'<span class="badge gap-{_html_attr(gap.get("priority", "unknown"))}">{_html(gap.get("priority", "unknown"))}</span>'
        "</div>"
        '<div class="badges">'
        f'<span class="badge">{_html(gap.get("type", "unknown"))}</span>'
        f'<span class="badge">report {_html(gap.get("report_label", ""))}</span>'
        "</div>"
        f'<p>{_html(gap.get("reason", ""))}</p>'
        '<div class="meta">'
        f'<span>id {_html(gap.get("id", ""))}</span>'
        f'<span>requested evidence {_html(gap.get("requested_evidence", ""))}</span>'
        "</div>"
        "</article>"
    )


def _portfolio_remediation_card(action: dict[str, Any]) -> str:
    search = _search_text(
        [
            action.get("id", ""),
            action.get("priority", ""),
            action.get("owner", ""),
            action.get("target", ""),
            action.get("category", ""),
            action.get("reason", ""),
            action.get("requested_evidence", ""),
            action.get("report_label", ""),
        ]
    )
    return (
        '<article class="portfolio-item" data-kind="remediation" '
        f'data-owner="{_attr_value(action.get("owner", ""))}" '
        'data-business="" data-environment="" data-tier="" data-state="" data-risk="" '
        'data-gap-priority="" data-gap-type="" '
        f'data-search="{_html_attr(search)}">'
        '<div class="item-head">'
        f'<strong>{_html(action.get("reason", ""))}</strong>'
        f'<span class="badge tier-{_html_attr(action.get("priority", "P2"))}">{_html(action.get("priority", "P2"))}</span>'
        "</div>"
        '<div class="badges">'
        f'<span class="badge">owner {_html(action.get("owner", "unassigned"))}</span>'
        f'<span class="badge">category {_html(action.get("category", "unknown"))}</span>'
        f'<span class="badge">target {_html(action.get("target", "unknown"))}</span>'
        f'<span class="badge">report {_html(action.get("report_label", ""))}</span>'
        "</div>"
        '<div class="meta">'
        f'<span>id {_html(action.get("id", ""))}</span>'
        f'<span>requested evidence {_html(action.get("requested_evidence", ""))}</span>'
        "</div>"
        "</article>"
    )


def _metric_html(label: str, value: Any) -> str:
    return f'<div class="metric"><strong>{_html(value)}</strong><span>{_html(label)}</span></div>'


def _select_html(name: str, label: str, values: list[str]) -> str:
    options = ['<option value="">All</option>']
    options.extend(f'<option value="{_attr_value(value)}">{_html(_human_label(value))}</option>' for value in values)
    return f'<label>{_html(label)}<select id="filter-{_html_attr(name)}">{"".join(options)}</select></label>'


def _rollup_table_html(title: str, rows: list[dict[str, Any]]) -> str:
    if not rows:
        return f'<div><h3>{_html(title)}</h3><p class="empty">None.</p></div>'
    body = "".join(
        "<tr>"
        f'<td>{_html(row.get("key", "unknown"))}</td>'
        f'<td>{_html(row.get("findings", 0))}</td>'
        f'<td>{_html(row.get("urgent", 0))}</td>'
        f'<td>{_html(row.get("high", 0))}</td>'
        f'<td>{_html(row.get("accepted_risk", 0))}</td>'
        f'<td>{_html(row.get("expired_accepted_risk", 0))}</td>'
        "</tr>"
        for row in rows[:8]
    )
    return (
        f"<div><h3>{_html(title)}</h3><table>"
        "<thead><tr><th>Key</th><th>Findings</th><th>Urgent</th><th>High</th><th>Accepted</th><th>Expired</th></tr></thead>"
        f"<tbody>{body}</tbody></table></div>"
    )


def _gap_rollup_table_html(title: str, rows: list[dict[str, Any]]) -> str:
    if not rows:
        return f'<div><h3>{_html(title)}</h3><p class="empty">None.</p></div>'
    body = "".join(
        "<tr>"
        f'<td>{_html(row.get("key", "unknown"))}</td>'
        f'<td>{_html(row.get("visibility_gaps", 0))}</td>'
        f'<td>{_html(row.get("critical_gap", 0))}</td>'
        f'<td>{_html(row.get("high_gap", 0))}</td>'
        f'<td>{_html(row.get("reports", 0))}</td>'
        "</tr>"
        for row in rows[:8]
    )
    return (
        f"<div><h3>{_html(title)}</h3><table>"
        "<thead><tr><th>Key</th><th>Gaps</th><th>Critical</th><th>High</th><th>Reports</th></tr></thead>"
        f"<tbody>{body}</tbody></table></div>"
    )


def _manifest_rollup_table_html(title: str, rows: list[dict[str, Any]]) -> str:
    if not rows:
        return f'<div><h3>{_html(title)}</h3><p class="empty">None.</p></div>'
    body = "".join(
        "<tr>"
        f'<td>{_html(row.get("key", "not_provided"))}</td>'
        f'<td>{_html(row.get("reports", 0))}</td>'
        f'<td>{_html(row.get("changed", 0))}</td>'
        f'<td>{_html(row.get("missing", 0))}</td>'
        f'<td>{_html(row.get("unmanifested", 0))}</td>'
        f'<td>{_html(row.get("errors", 0))}</td>'
        "</tr>"
        for row in rows[:8]
    )
    return (
        f"<div><h3>{_html(title)}</h3><table>"
        "<thead><tr><th>Status</th><th>Reports</th><th>Changed</th><th>Missing</th><th>Unmanifested</th><th>Errors</th></tr></thead>"
        f"<tbody>{body}</tbody></table></div>"
    )


def _remediation_rollup_table_html(title: str, rows: list[dict[str, Any]]) -> str:
    if not rows:
        return f'<div><h3>{_html(title)}</h3><p class="empty">None.</p></div>'
    body = "".join(
        "<tr>"
        f'<td>{_html(row.get("key", "unknown"))}</td>'
        f'<td>{_html(row.get("actions", 0))}</td>'
        f'<td>{_html(row.get("p1", 0))}</td>'
        f'<td>{_html(row.get("p2", 0))}</td>'
        f'<td>{_html(row.get("p3", 0))}</td>'
        f'<td>{_html(row.get("reports", 0))}</td>'
        "</tr>"
        for row in rows[:8]
    )
    return (
        f"<div><h3>{_html(title)}</h3><table>"
        "<thead><tr><th>Key</th><th>Actions</th><th>P1</th><th>P2</th><th>P3</th><th>Reports</th></tr></thead>"
        f"<tbody>{body}</tbody></table></div>"
    )


def _portfolio_report_rows(reports: list[dict[str, Any]]) -> str:
    if not reports:
        return '<p class="empty">No reports.</p>'
    body = "".join(
        "<tr>"
        f'<td>{_html(report.get("label", ""))}</td>'
        f'<td>{_html(report.get("decision", "unknown"))}</td>'
        f'<td>{_html(report.get("findings", 0))}</td>'
        f'<td>{_html(report.get("urgent", 0))}</td>'
        f'<td>{_html(report.get("high", 0))}</td>'
        f'<td>{_html(report.get("visibility_gaps", 0))}</td>'
        f'<td>{_html(report.get("manifest_status", "not_provided"))}</td>'
        f'<td>{_html(report.get("remediation_actions", 0))}</td>'
        f'<td>{_html(report.get("remediation_p1", 0))}</td>'
        "</tr>"
        for report in reports[:20]
    )
    return (
        "<table><thead><tr><th>Report</th><th>Decision</th><th>Findings</th><th>Urgent</th><th>High</th>"
        f"<th>Gaps</th><th>Manifest</th><th>Actions</th><th>P1</th></tr></thead><tbody>{body}</tbody></table>"
    )


def _unique_values(items: list[dict[str, Any]], key: str, rank: dict[str, int] | None = None) -> list[str]:
    values = {_known(item.get(key)) for item in items if _known(item.get(key)) != "unknown"}
    return sorted(values, key=lambda value: (rank.get(value, 99) if rank else 99, value))


def _search_text(values: list[Any]) -> str:
    return " ".join(str(value) for value in values).lower()


def _html(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _html_attr(value: Any) -> str:
    return _html(value)


def _attr_value(value: Any) -> str:
    return _html_attr(_known(value).lower())


def _human_label(value: Any) -> str:
    return str(value).replace("_", " ").replace("-", " ").title()


def _read_report_if_valid(path: Path) -> dict[str, Any] | None:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(report, dict):
        return None
    if not isinstance(report.get("summary"), dict):
        return None
    if not isinstance(report.get("findings"), list):
        return None
    if not isinstance(report.get("attack_paths"), list):
        return None
    report = dict(report)
    report["_portfolio_source"] = str(path)
    report["_portfolio_label"] = path.stem
    return report


def _report_entry(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary") or {}
    decision = report.get("review_decision") or {}
    findings = [finding for finding in report.get("findings", []) if isinstance(finding, dict)]
    gaps = [gap for gap in report.get("visibility_gaps", []) if isinstance(gap, dict)]
    manifest = _manifest_entry(report)
    remediation = _remediation_plan_summary(report)
    return {
        "label": report.get("_portfolio_label", ""),
        "path": report.get("_portfolio_source", ""),
        "decision": decision.get("decision", "unknown"),
        "review_label": decision.get("label", ""),
        "agents": _int(summary.get("agents", 0)),
        "findings": len(findings),
        "urgent": sum(1 for finding in findings if finding.get("tier") == "urgent"),
        "high": sum(1 for finding in findings if finding.get("tier") == "high"),
        "medium": sum(1 for finding in findings if finding.get("tier") == "medium"),
        "low": sum(1 for finding in findings if finding.get("tier") == "low"),
        "informational": sum(1 for finding in findings if finding.get("tier") == "informational"),
        "accepted_risk": sum(1 for finding in findings if finding.get("risk_status") == "accepted"),
        "expired_accepted_risk": sum(1 for finding in findings if finding.get("risk_status") == "acceptance_expired"),
        "visibility_gaps": len(gaps),
        "critical_gaps": sum(1 for gap in gaps if gap.get("priority") == "critical_gap"),
        "high_gaps": sum(1 for gap in gaps if gap.get("priority") == "high_gap"),
        "manifest_status": manifest["status"],
        "manifest_changed": manifest["changed_count"],
        "manifest_missing": manifest["missing_count"],
        "manifest_unmanifested": manifest["unmanifested_count"],
        "manifest_errors": manifest["error_count"],
        "remediation_actions": remediation["actions"],
        "remediation_p1": remediation["p1"],
        "remediation_p2": remediation["p2"],
        "remediation_p3": remediation["p3"],
    }


def _finding_entry(report: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any]:
    context = finding.get("operational_context") or {}
    return {
        "id": str(finding.get("id", "")),
        "title": str(finding.get("title", "")),
        "tier": str(finding.get("tier", "unknown")),
        "score": _int(finding.get("score", 0)),
        "path_state": str(finding.get("path_state", "unknown") or "unknown"),
        "evidence_quality": str(finding.get("evidence_quality", "unknown") or "unknown"),
        "risk_status": str(finding.get("risk_status", "open") or "open"),
        "accepted_risk": finding.get("accepted_risk", {}) if isinstance(finding.get("accepted_risk", {}), dict) else {},
        "owner": _known(context.get("owner")),
        "environment": _known(context.get("environment")),
        "business_unit": _known(context.get("business_unit")),
        "report_label": str(report.get("_portfolio_label", "")),
        "report_path": str(report.get("_portfolio_source", "")),
        "visibility_gaps": finding.get("visibility_gaps", []) if isinstance(finding.get("visibility_gaps", []), list) else [],
        "visibility_gap_priorities": finding.get("visibility_gap_priorities", [])
        if isinstance(finding.get("visibility_gap_priorities", []), list)
        else [],
    }


def _gap_entry(report: dict[str, Any], gap: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(gap.get("id", "")),
        "priority": str(gap.get("priority", "unknown") or "unknown"),
        "type": str(gap.get("type", "unknown") or "unknown"),
        "target": str(gap.get("target", "")),
        "reason": str(gap.get("reason", "")),
        "requested_evidence": str(gap.get("requested_evidence", "")),
        "report_label": str(report.get("_portfolio_label", "")),
        "report_path": str(report.get("_portfolio_source", "")),
        "affected_findings": gap.get("affected_findings", []) if isinstance(gap.get("affected_findings", []), list) else [],
    }


def _manifest_entry(report: dict[str, Any]) -> dict[str, Any]:
    manifest = report.get("evidence_manifest")
    if not isinstance(manifest, dict):
        manifest = {}
    summary = manifest.get("summary") if isinstance(manifest.get("summary"), dict) else {}
    status = str(manifest.get("status") or "not_provided")
    if status not in {"present", "missing", "not_provided"}:
        status = "not_provided"
    return {
        "status": status,
        "path": str(manifest.get("path") or ""),
        "changed_count": _int(summary.get("changed_count", 0)),
        "missing_count": _int(summary.get("missing_count", 0)),
        "unmanifested_count": _int(summary.get("unmanifested_count", 0)),
        "error_count": len(manifest.get("errors", [])) if isinstance(manifest.get("errors"), list) else 0,
        "report_label": str(report.get("_portfolio_label", "")),
    }


def _remediation_plan_summary(report: dict[str, Any]) -> dict[str, int]:
    plan = report.get("remediation_plan")
    if not isinstance(plan, dict):
        return {"actions": 0, "p1": 0, "p2": 0, "p3": 0}
    summary = plan.get("summary") if isinstance(plan.get("summary"), dict) else {}
    actions = [action for action in plan.get("actions", []) if isinstance(action, dict)] if isinstance(plan.get("actions"), list) else []
    if actions:
        return {
            "actions": len(actions),
            "p1": sum(1 for action in actions if action.get("priority") == "P1"),
            "p2": sum(1 for action in actions if action.get("priority") == "P2"),
            "p3": sum(1 for action in actions if action.get("priority") == "P3"),
        }
    return {
        "actions": _int(summary.get("actions", 0)),
        "p1": _int(summary.get("p1", 0)),
        "p2": _int(summary.get("p2", 0)),
        "p3": _int(summary.get("p3", 0)),
    }


def _remediation_action_entry(report: dict[str, Any], action: dict[str, Any]) -> dict[str, Any]:
    owner = _known(action.get("owner"))
    return {
        "id": str(action.get("id", "")),
        "priority": str(action.get("priority", "P2") or "P2") if action.get("priority") in {"P1", "P2", "P3"} else "P2",
        "owner": "unassigned" if owner == "unknown" else owner,
        "target": _known(action.get("target")),
        "category": _known(action.get("category")),
        "reason": str(action.get("reason", "")),
        "requested_evidence": str(action.get("requested_evidence", "")),
        "report_label": str(report.get("_portfolio_label", "")),
        "report_path": str(report.get("_portfolio_source", "")),
    }


def _count_values(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key, "unknown"))
        counts[value] = counts.get(value, 0) + 1
    return counts


def _rollup(items: list[dict[str, Any]], key: str, rank: dict[str, int] | None = None) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for item in items:
        value = _known(item.get(key))
        row = rows.setdefault(
            value,
            {
                "key": value,
                "findings": 0,
                "urgent": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0,
                "accepted_risk": 0,
                "expired_accepted_risk": 0,
                "visibility_gaps": 0,
                "_reports": set(),
            },
        )
        row["findings"] += 1
        if item.get("tier") in {"urgent", "high", "medium", "low", "informational"}:
            row[item["tier"]] += 1
        if item.get("risk_status") == "accepted":
            row["accepted_risk"] += 1
        if item.get("risk_status") == "acceptance_expired":
            row["expired_accepted_risk"] += 1
        row["visibility_gaps"] += len(item.get("visibility_gaps", []))
        if item.get("report_label"):
            row["_reports"].add(item["report_label"])
    normalized = []
    for row in rows.values():
        clean = dict(row)
        clean["reports"] = len(clean.pop("_reports"))
        normalized.append(clean)
    return sorted(
        normalized,
        key=lambda row: (
            rank.get(row["key"], 99) if rank else 99,
            -row["urgent"],
            -row["high"],
            -row["findings"],
            row["key"],
        ),
    )


def _gap_rollup(items: list[dict[str, Any]], key: str, rank: dict[str, int] | None = None) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for item in items:
        value = _known(item.get(key))
        row = rows.setdefault(value, {"key": value, "visibility_gaps": 0, "critical_gap": 0, "high_gap": 0, "_reports": set()})
        row["visibility_gaps"] += 1
        if item.get("priority") in {"critical_gap", "high_gap"}:
            row[item["priority"]] += 1
        if item.get("report_label"):
            row["_reports"].add(item["report_label"])
    normalized = []
    for row in rows.values():
        clean = dict(row)
        clean["reports"] = len(clean.pop("_reports"))
        normalized.append(clean)
    return sorted(
        normalized,
        key=lambda row: (
            rank.get(row["key"], 99) if rank else 99,
            -row.get("critical_gap", 0),
            -row.get("high_gap", 0),
            -row["visibility_gaps"],
            row["key"],
        ),
    )


def _manifest_status_rollup(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for item in items:
        status = str(item.get("status", "not_provided"))
        row = rows.setdefault(
            status,
            {"key": status, "reports": 0, "changed": 0, "missing": 0, "unmanifested": 0, "errors": 0},
        )
        row["reports"] += 1
        row["changed"] += _int(item.get("changed_count", 0))
        row["missing"] += _int(item.get("missing_count", 0))
        row["unmanifested"] += _int(item.get("unmanifested_count", 0))
        row["errors"] += _int(item.get("error_count", 0))
    status_rank = {"present": 0, "missing": 1, "not_provided": 2}
    return sorted(rows.values(), key=lambda row: (status_rank.get(row["key"], 99), row["key"]))


def _remediation_rollup(items: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for item in items:
        value = _known(item.get(key))
        if key == "owner" and value == "unknown":
            value = "unassigned"
        row = rows.setdefault(value, {"key": value, "actions": 0, "p1": 0, "p2": 0, "p3": 0, "_reports": set()})
        row["actions"] += 1
        priority = str(item.get("priority", "P2")).lower()
        if priority in {"p1", "p2", "p3"}:
            row[priority] += 1
        if item.get("report_label"):
            row["_reports"].add(item["report_label"])
    normalized = []
    for row in rows.values():
        clean = dict(row)
        clean["reports"] = len(clean.pop("_reports"))
        normalized.append(clean)
    return sorted(normalized, key=lambda row: (-row["p1"], -row["actions"], row["key"]))


def _top_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda item: (
            TIER_ORDER.get(item["tier"], 99),
            RISK_STATUS_ORDER.get(item.get("risk_status", "open"), 9),
            -item["score"],
            item["report_label"],
            item["id"],
        ),
    )[:15]


def _top_gaps(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        gaps,
        key=lambda item: (GAP_ORDER.get(item["priority"], 99), item["report_label"], item["id"]),
    )[:15]


def _top_remediation_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    priority_order = {"P1": 0, "P2": 1, "P3": 2}
    return sorted(
        actions,
        key=lambda item: (
            priority_order.get(item["priority"], 9),
            item["owner"],
            item["category"],
            item["target"],
            item["report_label"],
            item["id"],
        ),
    )[:15]


def _portfolio_review(summary: dict[str, int], findings: list[dict[str, Any]], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    top_owners = [row["key"] for row in _rollup(findings, "owner") if row["key"] != "unknown"][:3]
    critical_or_high_gaps = [gap for gap in gaps if gap["priority"] in {"critical_gap", "high_gap"}]
    if summary.get("expired_accepted_risk_findings", 0):
        return {
            "decision": "owner_followup_required",
            "label": "Expired accepted risk",
            "reason": "One or more reports contain expired accepted-risk metadata.",
            "required_actions": [
                "Route expired accepted-risk findings to owning teams.",
                "Renew, revoke, or close expired risk records.",
                "Re-run portfolio after updated reports are generated.",
            ],
            "top_owners": top_owners,
        }
    if summary.get("urgent", 0):
        return {
            "decision": "urgent_review_required",
            "label": "Urgent review required",
            "reason": "One or more reports contain urgent findings.",
            "required_actions": [
                "Assign owners for urgent findings.",
                "Prioritize critical and high visibility gaps.",
                "Re-run scans after remediation evidence is added.",
            ],
            "top_owners": top_owners,
        }
    if summary.get("high", 0) or critical_or_high_gaps:
        return {
            "decision": "owner_followup_required",
            "label": "Owner follow-up required",
            "reason": "The portfolio contains high findings or high-priority evidence gaps.",
            "required_actions": [
                "Route high findings to owning teams.",
                "Request missing identity, approval, data, or runtime evidence.",
                "Track remaining gaps before approval.",
            ],
            "top_owners": top_owners,
        }
    if summary.get("findings", 0):
        return {
            "decision": "monitor",
            "label": "Monitor portfolio",
            "reason": "Only low or medium findings are present.",
            "required_actions": ["Refresh evidence periodically."],
            "top_owners": top_owners,
        }
    return {
        "decision": "no_findings",
        "label": "No findings",
        "reason": "No findings were present in the loaded reports.",
        "required_actions": ["Confirm the report set is complete."],
        "top_owners": top_owners,
    }


def _known(value: Any) -> str:
    text = str(value or "").strip()
    return text if text else "unknown"


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
