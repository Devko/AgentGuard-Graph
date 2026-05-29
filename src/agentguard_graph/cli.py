"""Command-line interface for AgentGuard Graph."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from importlib.resources import files
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from . import __version__
from .adapters.copilot import parse_copilot_agent
from .adapters.data_privacy_exports import (
    parse_data_catalog_export,
    parse_dlp_export,
    parse_sensitivity_label_export,
    parse_table_classification_export,
)
from .adapters.framework_code import TOP_AGENT_FRAMEWORKS, parse_framework_code
from .adapters.langgraph_config import parse_langgraph_config
from .adapters.identity_exports import (
    parse_aws_iam_policy_export,
    parse_azure_rbac_export,
    parse_confluence_permissions_export,
    parse_databricks_permissions_export,
    parse_dataverse_permissions_export,
    parse_gcp_iam_policy_export,
    parse_github_app_export,
    parse_jira_permissions_export,
    parse_kubernetes_rbac_export,
    parse_microsoft_365_permission_export,
    parse_netsuite_permissions_export,
    parse_okta_permissions_export,
    parse_oauth_scope_export,
    parse_power_platform_permissions_export,
    parse_servicenow_permissions_export,
    parse_salesforce_permissions_export,
    parse_snowflake_grants_export,
    parse_stripe_permissions_export,
    parse_zendesk_permissions_export,
)
from .adapters.mcp_config import parse_mcp_client_config
from .adapters.openclaw_config import parse_openclaw_config
from .adapters.openapi import parse_openapi
from .adapters.policy_evaluation import parse_cedar_policy, parse_opa_policy
from .adapters.runtime_exports import (
    parse_agent_trace_export,
    parse_approval_broker_export,
    parse_ci_system_log,
    parse_cloud_audit_log,
    parse_mcp_host_log,
)
from .adapters.tool_manifest import parse_tool_manifest
from .doctor import build_doctor_report
from .errors import AgentGuardError, EvidenceLoadError
from .compare import compare_reports, load_compare_report, write_compare_markdown
from .graph.builder import build_graph, build_inventory
from .graph.findings import assemble_report
from .graph.paths import analyze_attack_paths
from .manifest import validate_evidence_manifest, write_evidence_manifest
from .outputs.html import write_html_report
from .outputs.json_report import write_json_report
from .outputs.markdown import write_markdown_report
from .portfolio import build_portfolio_report, load_portfolio_reports, write_portfolio_html, write_portfolio_markdown
from .schemas import AUTONOMY_VALUES, ENVIRONMENT_VALUES, infer_target_system
from .validation.validate_inputs import load_evidence, validate_evidence

TRUST_VALUES = {"trusted", "untrusted", "mixed", "unknown"}


def add_evidence_args(parser: argparse.ArgumentParser, include_policy: bool = True, include_events: bool = True) -> None:
    parser.add_argument("--evidence-dir", help="Directory containing a conventional AgentGuard evidence pack")
    parser.add_argument("--agents", help="Agent evidence JSON file")
    parser.add_argument("--mcp", help="MCP server evidence JSON file")
    parser.add_argument("--openapi", help="OpenAPI JSON file or directory")
    parser.add_argument("--identity", help="Identity evidence JSON file")
    parser.add_argument("--data-catalog", help="Data catalog JSON file")
    if include_policy:
        parser.add_argument("--approval-policy", help="Approval policy JSON file")
    if include_events:
        parser.add_argument("--events", help="Runtime event JSONL file")


def _load_from_args(args: argparse.Namespace) -> dict[str, Any]:
    pack = _evidence_pack_paths(getattr(args, "evidence_dir", None))
    return load_evidence(
        agents=getattr(args, "agents", None) or pack.get("agents"),
        mcp=getattr(args, "mcp", None) or pack.get("mcp"),
        openapi=getattr(args, "openapi", None) or pack.get("openapi"),
        identity=getattr(args, "identity", None) or pack.get("identity"),
        data_catalog=getattr(args, "data_catalog", None) or pack.get("data_catalog"),
        approval_policy=getattr(args, "approval_policy", None) or pack.get("approval_policy"),
        events=getattr(args, "events", None) or pack.get("events"),
    )


def _evidence_pack_paths(evidence_dir: str | None) -> dict[str, str]:
    if not evidence_dir:
        return {}
    base = Path(evidence_dir)
    if not base.exists():
        raise EvidenceLoadError(f"{base}: evidence directory not found")
    if not base.is_dir():
        raise EvidenceLoadError(f"{base}: evidence path must be a directory")
    candidates = {
        "agents": base / "agentguard.json",
        "mcp": base / "mcp-servers.json",
        "identity": base / "identity.json",
        "data_catalog": base / "data-catalog.json",
        "approval_policy": base / "approval-policy.json",
        "events": base / "events.jsonl",
    }
    paths = {name: str(path) for name, path in candidates.items() if path.exists()}
    openapi_dir = base / "openapi"
    openapi_file = base / "openapi.json"
    if openapi_dir.exists():
        paths["openapi"] = str(openapi_dir)
    elif openapi_file.exists():
        paths["openapi"] = str(openapi_file)
    return paths


def _build_report(evidence: dict[str, Any], evidence_manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    graph, graph_gaps = build_graph(evidence)
    attack_paths, findings, visibility_gaps = analyze_attack_paths(evidence, graph_gaps)
    return assemble_report(evidence, graph, findings, attack_paths, visibility_gaps, evidence_manifest=evidence_manifest)


def _scan_manifest_files(args: argparse.Namespace) -> list[Path]:
    evidence_dir = getattr(args, "evidence_dir", None)
    if not evidence_dir:
        return []
    base = Path(evidence_dir)
    candidates = [
        base / "agentguard.json",
        base / "mcp-servers.json",
        base / "identity.json",
        base / "data-catalog.json",
        base / "approval-policy.json",
        base / "events.jsonl",
        base / "collector-summary.json",
        base / "openapi.json",
    ]
    openapi_dir = base / "openapi"
    if openapi_dir.is_dir():
        candidates.extend(sorted(openapi_dir.glob("*.json")))
    return candidates


def cmd_scan(args: argparse.Namespace) -> int:
    evidence = _load_from_args(args)
    validation = validate_evidence(evidence)
    _require_agent_evidence(validation, evidence, "scan")
    if validation.errors:
        _print_validation_status(validation, "failed")
        _print_validation(validation.to_dict())
        return 2
    manifest_status = validate_evidence_manifest(getattr(args, "evidence_dir", None), _scan_manifest_files(args))
    report = _build_report(evidence, evidence_manifest=manifest_status)
    if args.out:
        write_json_report(report, args.out)
    if args.markdown:
        write_markdown_report(report, args.markdown)
    if args.html:
        write_html_report(report, args.html)
    print(f"wrote report: {args.out}")
    _print_report_summary(report)
    if args.markdown:
        print(f"wrote markdown: {args.markdown}")
    if args.html:
        print(f"wrote html: {args.html}")
    return 0


def cmd_inventory(args: argparse.Namespace) -> int:
    evidence = _load_from_args(args)
    validation = validate_evidence(evidence)
    _require_agent_evidence(validation, evidence, "inventory")
    if validation.errors:
        _print_validation_status(validation, "failed")
        _print_validation(validation.to_dict())
        return 2
    graph, visibility_gaps = build_graph(evidence)
    output = {
        "schema_version": "0.1",
        "inventory": build_inventory(evidence),
        "graph": graph.to_dict(),
        "visibility_gaps": [gap.to_dict() for gap in visibility_gaps],
    }
    write_json_report(output, args.out)
    print(f"wrote inventory: {args.out}")
    return 0


def _print_validation(result: dict[str, list[str]]) -> None:
    labels = {"errors": "error", "warnings": "warning", "info": "info"}
    for level in ["errors", "warnings", "info"]:
        for item in result.get(level, []):
            print(f"{labels[level]}: {item}")


def _require_agent_evidence(validation: Any, evidence: dict[str, Any], command: str) -> None:
    agents_payload = evidence.get("agents", {})
    agents = agents_payload.get("agents", []) if isinstance(agents_payload, dict) else []
    if agents:
        return
    source_file = agents_payload.get("source_file") if isinstance(agents_payload, dict) else None
    if source_file:
        validation.errors.append(
            f"{command} requires at least one agent in {source_file}; add an agent entry before running {command}."
        )
        return
    validation.errors.append(
        f"{command} requires agent evidence. Provide --agents agentguard.json or --evidence-dir containing agentguard.json."
    )


def _print_validation_status(validation: Any, status: str) -> None:
    print(
        f"validation: {status} "
        f"({len(validation.errors)} errors, {len(validation.warnings)} warnings, {len(validation.info)} info)"
    )


def _print_report_summary(report: dict[str, Any]) -> None:
    summary = report.get("summary", {})
    if not summary:
        return
    print(
        "report summary: "
        f"agents={summary.get('agents', 0)} "
        f"tools={summary.get('tools', 0)} "
        f"findings={summary.get('findings', 0)} "
        f"urgent={summary.get('urgent', 0)} "
        f"high={summary.get('high', 0)} "
        f"visibility_gaps={summary.get('visibility_gaps', 0)} "
        f"generic_tools={summary.get('generic_tools', 0)} "
        f"tools_missing_controls={summary.get('tools_missing_required_controls', 0)} "
        f"prompt_boundary_risks={summary.get('prompt_boundary_risks', 0)} "
        f"policy_rule_risks={summary.get('policy_rule_risks', 0)} "
        f"policy_evaluation_gaps={summary.get('policy_evaluation_gaps', 0)}"
    )


def cmd_validate(args: argparse.Namespace) -> int:
    evidence = _load_from_args(args)
    validation = validate_evidence(evidence)
    if args.json:
        print(json.dumps(validation.to_dict(), indent=2, sort_keys=True))
    else:
        if validation.ok:
            _print_validation_status(validation, "ok")
        else:
            _print_validation_status(validation, "failed")
        _print_validation(validation.to_dict())
    if validation.ok:
        return 0
    return 2


def cmd_doctor(args: argparse.Namespace) -> int:
    evidence_paths = _doctor_evidence_paths(args)
    evidence = load_evidence(
        agents=evidence_paths.get("agents"),
        mcp=evidence_paths.get("mcp"),
        openapi=evidence_paths.get("openapi"),
        identity=evidence_paths.get("identity"),
        data_catalog=evidence_paths.get("data_catalog"),
        approval_policy=evidence_paths.get("approval_policy"),
        events=evidence_paths.get("events"),
    )
    validation = validate_evidence(evidence)
    discovered_inputs = _discover_project_inputs(args.project_dir) if args.project_dir else None
    report = build_doctor_report(
        evidence=evidence,
        validation=validation,
        evidence_paths=evidence_paths,
        evidence_dir=getattr(args, "evidence_dir", None),
        project_dir=getattr(args, "project_dir", None),
        discovered_inputs=discovered_inputs,
        profile=getattr(args, "profile", None),
    )
    plan_path = _doctor_plan_path(getattr(args, "write_plan", None), getattr(args, "evidence_dir", None), getattr(args, "project_dir", None))
    if plan_path:
        write_json_report(report["collection_plan"], plan_path)
    if args.out:
        write_json_report(report, args.out)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_doctor_report(report)
        if plan_path:
            print(f"wrote collection plan: {plan_path}")
        if args.out:
            print(f"wrote doctor report: {args.out}")
    if report["secret_findings"] and args.fail_on_secrets:
        return 3
    if validation.errors:
        return 2
    return 0


def _doctor_evidence_paths(args: argparse.Namespace) -> dict[str, str]:
    pack = _evidence_pack_paths(getattr(args, "evidence_dir", None))
    return {
        "agents": getattr(args, "agents", None) or pack.get("agents", ""),
        "mcp": getattr(args, "mcp", None) or pack.get("mcp", ""),
        "openapi": getattr(args, "openapi", None) or pack.get("openapi", ""),
        "identity": getattr(args, "identity", None) or pack.get("identity", ""),
        "data_catalog": getattr(args, "data_catalog", None) or pack.get("data_catalog", ""),
        "approval_policy": getattr(args, "approval_policy", None) or pack.get("approval_policy", ""),
        "events": getattr(args, "events", None) or pack.get("events", ""),
    }


def _doctor_plan_path(write_plan: Any, evidence_dir: str | None, project_dir: str | None) -> str:
    if write_plan in {None, False}:
        return ""
    if isinstance(write_plan, str) and write_plan:
        return write_plan
    if evidence_dir:
        return str(Path(evidence_dir) / "collection-plan.json")
    if project_dir:
        return str(Path(project_dir) / "collection-plan.json")
    return "collection-plan.json"


def _print_doctor_report(report: dict[str, Any]) -> None:
    print(f"doctor: {report['status']}")
    print(f"package_ready: {'yes' if report.get('package_ready') else 'no'}")
    summary = report.get("summary", {})
    if summary:
        print(
            "doctor summary: "
            f"evidence_files={summary.get('evidence_files_checked', 0)} "
            f"secrets={summary.get('secret_findings', 0)} "
            f"validation_errors={summary.get('validation_errors', 0)} "
            f"recommended_exports={summary.get('recommended_exports', 0)} "
            f"visibility_gaps={summary.get('visibility_gaps', 0)} "
            f"manifest={summary.get('manifest_status', 'missing')} "
            f"manifest_checked={summary.get('manifest_checked', 0)} "
            f"manifest_changed={summary.get('manifest_changed', 0)} "
            f"manifest_missing={summary.get('manifest_missing', 0)} "
            f"manifest_unmanifested={summary.get('manifest_unmanifested', 0)}"
        )
    for blocker in report.get("blockers", []):
        print(f"blocker: {blocker}")
    for finding in report.get("secret_findings", []):
        location = finding.get("file", "")
        if finding.get("line"):
            location = f"{location}:{finding['line']}"
        if finding.get("json_path"):
            location = f"{location} {finding['json_path']}"
        print(f"secret: {finding.get('severity')} {finding.get('label')} at {location}")
    if report.get("recommended_exports"):
        profile_view = report.get("profile_view", {})
        actions = profile_view.get("actions") or report.get("collection_plan", {}).get("actions", [])
        label = profile_view.get("label", "All roles")
        print(f"collection plan ({label}):")
        for action in actions[:12]:
            print(f"- [{action['priority']}] {action['file']} / {action['target']}")
            print(f"  owner: {action['owner']}")
            print(f"  reason: {action['reason']}")
            print(f"  repair: {action['repair_text']}")
            if action.get("command"):
                print(f"  command: {action['command']}")
        hidden = profile_view.get("hidden_action_count", 0)
        if hidden:
            print(f"  hidden for this profile: {hidden}")
    else:
        print("export next: none")
    checklists = report.get("profile_view", {}).get("framework_checklists") or report.get("framework_checklists", [])
    detected_checklists = [item for item in checklists if item.get("status") == "detected"]
    if detected_checklists:
        print("framework checklist:")
        for checklist in detected_checklists[:5]:
            print(f"- {checklist.get('label')} ({checklist.get('status')})")
            for step in checklist.get("steps", [])[:3]:
                status = "done" if step.get("done") else "next"
                print(f"  - {status}: {step.get('file')} / {step.get('owner')}: {step.get('reason')}")
    if report.get("next_commands"):
        print("next commands:")
        for command in report["next_commands"][:6]:
            print(f"- {command}")


def cmd_explain(args: argparse.Namespace) -> int:
    report_path = Path(args.findings)
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"{report_path}: cannot read findings report: {exc}", file=sys.stderr)
        return 2
    if not isinstance(report, dict):
        print(f"{report_path}: findings report must be a JSON object", file=sys.stderr)
        return 2
    attack_paths = report.get("attack_paths", [])
    findings = report.get("findings", [])
    if not isinstance(attack_paths, list):
        print(f"{report_path}: attack_paths must be a list", file=sys.stderr)
        return 2
    if not isinstance(findings, list):
        print(f"{report_path}: findings must be a list", file=sys.stderr)
        return 2
    path = next((item for item in attack_paths if isinstance(item, dict) and item.get("id") == args.path_id), None)
    finding = next(
        (
            item
            for item in findings
            if isinstance(item, dict) and item.get("id") == args.path_id.replace("path-", "finding-")
        ),
        None,
    )
    if not path:
        print(f"path not found: {args.path_id}", file=sys.stderr)
        available = [str(item.get("id")) for item in attack_paths if isinstance(item, dict) and item.get("id")]
        if available:
            print(f"available path ids: {', '.join(available[:10])}", file=sys.stderr)
        return 2
    print(f"{path.get('id')}: {path.get('title')}")
    print(f"tier={path.get('tier')} score={path.get('score')} confidence={path.get('confidence')}")
    print(f"observation_status={path.get('observation_status', 'possible_static')}")
    print(f"risk_status={path.get('risk_status', 'open')}")
    accepted_risk = path.get("accepted_risk") if isinstance(path.get("accepted_risk"), dict) else {}
    if accepted_risk and accepted_risk.get("status") != "open":
        print(
            "accepted_risk="
            f"{accepted_risk.get('status')} "
            f"expires_at={accepted_risk.get('expires_at') or 'unspecified'} "
            f"ticket={accepted_risk.get('ticket') or 'none'}"
        )
    print("path:")
    for item in path.get("evidence_summary", []):
        print(f"  -> {item}")
    print("evidence:")
    for item in (finding or {}).get("evidence", path.get("evidence_summary", [])):
        print(f"  - {item}")
    print("unknowns:")
    for item in path.get("unknowns", []):
        print(f"  - {item}")
    print("recommendations:")
    for item in path.get("recommendations", []):
        print(f"  - {item}")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    base_report, base_source_type = _load_compare_input(args.base, "base")
    head_report, head_source_type = _load_compare_input(args.head, "head")
    report = compare_reports(
        base_report,
        head_report,
        base_label=getattr(args, "base_label", None) or args.base,
        head_label=getattr(args, "head_label", None) or args.head,
        base_source_type=base_source_type,
        head_source_type=head_source_type,
    )
    write_json_report(report, args.out)
    if args.markdown:
        write_compare_markdown(report, args.markdown)
    print(f"wrote compare report: {args.out}")
    _print_compare_summary(report)
    if args.markdown:
        print(f"wrote compare markdown: {args.markdown}")
    return 0


def _load_compare_input(path: str, role: str) -> tuple[dict[str, Any], str]:
    input_path = Path(path)
    if input_path.exists() and input_path.is_dir():
        evidence = load_evidence(**_evidence_pack_paths(str(input_path)))
        validation = validate_evidence(evidence)
        _require_agent_evidence(validation, evidence, f"compare {role}")
        if validation.errors:
            detail = "; ".join(validation.errors[:3])
            raise EvidenceLoadError(f"{input_path}: cannot build {role} report from evidence pack: {detail}")
        return _build_report(evidence), "evidence_pack"
    return load_compare_report(input_path), "report"


def _print_compare_summary(report: dict[str, Any]) -> None:
    summary = report.get("summary", {})
    if not summary:
        return
    print(
        "compare summary: "
        f"findings={summary.get('base_findings', 0)}->{summary.get('head_findings', 0)} "
        f"new={summary.get('new_findings', 0)} "
        f"resolved={summary.get('resolved_findings', 0)} "
        f"improved={summary.get('improved_findings', 0)} "
        f"regressed={summary.get('regressed_findings', 0)} "
        f"visibility_gaps={summary.get('base_visibility_gaps', 0)}->{summary.get('head_visibility_gaps', 0)}"
    )


def cmd_portfolio(args: argparse.Namespace) -> int:
    reports = load_portfolio_reports(args.reports_dir, recursive=args.recursive)
    portfolio = build_portfolio_report(reports, source=args.reports_dir)
    write_json_report(portfolio, args.out)
    if args.markdown:
        write_portfolio_markdown(portfolio, args.markdown)
    if args.html:
        write_portfolio_html(portfolio, args.html)
    print(f"wrote portfolio report: {args.out}")
    _print_portfolio_summary(portfolio)
    if args.markdown:
        print(f"wrote portfolio markdown: {args.markdown}")
    if args.html:
        print(f"wrote portfolio html: {args.html}")
    return 0


def _print_portfolio_summary(report: dict[str, Any]) -> None:
    summary = report.get("summary", {})
    if not summary:
        return
    print(
        "portfolio summary: "
        f"reports={summary.get('reports', 0)} "
        f"findings={summary.get('findings', 0)} "
        f"urgent={summary.get('urgent', 0)} "
        f"high={summary.get('high', 0)} "
        f"visibility_gaps={summary.get('visibility_gaps', 0)} "
        f"accepted={summary.get('accepted_risk_findings', 0)} "
        f"expired_acceptances={summary.get('expired_accepted_risk_findings', 0)} "
        f"owners={summary.get('owners', 0)} "
        f"environments={summary.get('environments', 0)} "
        f"business_units={summary.get('business_units', 0)}"
    )


STARTER_FILES = {
    "agentguard.json": {
        "schema_version": "0.1",
        "agents": [
            {
                "id": "example-agent",
                "name": "Example Agent",
                "owner": "example-team",
                "runtime": "custom",
                "environment": "unknown",
                "autonomy": "unknown",
                "input_sources": ["example_input"],
                "tools": ["example.read"],
                "identities": [],
                "memory": [],
                "approval_policy": "example-policy",
            }
        ],
        "input_sources": [{"id": "example_input", "trust": "unknown", "description": "Replace with real input evidence"}],
        "memory_stores": [],
    },
    "mcp-servers.json": {
        "schema_version": "0.1",
        "servers": [
            {
                "id": "example-mcp",
                "name": "Example MCP",
                "transport": "stdio",
                "auth": "unknown",
                "tools": [{"name": "example.read", "description": "Read example data", "risk_tags": ["read_action"]}],
            }
        ],
    },
    "identity.json": {"schema_version": "0.1", "identities": []},
    "data-catalog.json": {"schema_version": "0.1", "data_sources": []},
    "approval-policy.json": {"schema_version": "0.1", "policies": [{"id": "example-policy", "rules": []}]},
}


def cmd_init(args: argparse.Namespace) -> int:
    output_dir = _ensure_output_dir(args.out, "output directory")
    if getattr(args, "sample", None):
        sample_files = _sample_file_payloads(args.sample)
        if not sample_files:
            print(f"sample evidence pack not found: {args.sample}", file=sys.stderr)
            return 2
        for file_name, payload in sample_files:
            _write_bytes(output_dir / file_name, payload)
        print(f"created sample evidence pack: {output_dir}")
        return 0
    for name, data in STARTER_FILES.items():
        _write_json(output_dir / name, data)
    _write_text(output_dir / "events.jsonl", "")
    print(f"created starter evidence pack: {output_dir}")
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    output_dir = _ensure_output_dir(args.out, "output evidence directory")
    openapi_dir = output_dir / "openapi"

    warnings: list[str] = []
    project_dir = _arg_value(args, "project_dir")
    discovered_inputs = _discover_project_inputs(project_dir)
    mcp_servers: list[dict[str, Any]] = []
    tool_ids: set[str] = set()
    mcp_config_paths = _unique_paths(_arg_list(args, "mcp_config") + _arg_list(args, "claude_config") + discovered_inputs["mcp_config"])
    openclaw_config_paths = _unique_paths(_arg_list(args, "openclaw_config") + discovered_inputs["openclaw_config"])
    tool_manifest_paths = _unique_paths(_arg_list(args, "langchain_manifest") + discovered_inputs["tool_manifest"])
    openapi_paths = _unique_paths(_arg_list(args, "openapi") + discovered_inputs["openapi"])
    langgraph_paths = _unique_paths(_arg_list(args, "langgraph_config") + discovered_inputs["langgraph_config"])
    copilot_paths = _unique_paths(_arg_list(args, "copilot_agent") + discovered_inputs["copilot_agent"])
    framework_code_paths = _unique_paths(_arg_list(args, "framework_code") + discovered_inputs["framework_code"])
    data_classification_paths = {
        "data_catalog": _unique_paths(_arg_list(args, "data_catalog_export") + discovered_inputs["data_catalog_export"]),
        "dlp": _unique_paths(_arg_list(args, "dlp_export") + discovered_inputs["dlp_export"]),
        "sensitivity_label": _unique_paths(_arg_list(args, "sensitivity_label_export") + discovered_inputs["sensitivity_label_export"]),
        "table_classification": _unique_paths(_arg_list(args, "table_classification_export") + discovered_inputs["table_classification_export"]),
    }
    identity_export_paths = {
        "github_app": _unique_paths(_arg_list(args, "github_app_export") + discovered_inputs["github_app_export"]),
        "oauth_scopes": _unique_paths(_arg_list(args, "oauth_scopes_export") + discovered_inputs["oauth_scopes_export"]),
        "salesforce": _unique_paths(_arg_list(args, "salesforce_permissions_export") + discovered_inputs["salesforce_permissions_export"]),
        "aws_iam": _unique_paths(_arg_list(args, "aws_iam_policy") + discovered_inputs["aws_iam_policy"]),
        "kubernetes_rbac": _unique_paths(_arg_list(args, "kubernetes_rbac") + discovered_inputs["kubernetes_rbac"]),
        "microsoft_365": _unique_paths(_arg_list(args, "microsoft_365_permissions") + discovered_inputs["microsoft_365_permissions"]),
        "azure_rbac": _unique_paths(_arg_list(args, "azure_rbac") + discovered_inputs["azure_rbac"]),
        "gcp_iam": _unique_paths(_arg_list(args, "gcp_iam_policy") + discovered_inputs["gcp_iam_policy"]),
        "dataverse": _unique_paths(_arg_list(args, "dataverse_permissions") + discovered_inputs["dataverse_permissions"]),
        "power_platform": _unique_paths(_arg_list(args, "power_platform_permissions") + discovered_inputs["power_platform_permissions"]),
        "okta": _unique_paths(_arg_list(args, "okta_permissions") + discovered_inputs["okta_permissions"]),
        "jira": _unique_paths(_arg_list(args, "jira_permissions") + discovered_inputs["jira_permissions"]),
        "confluence": _unique_paths(_arg_list(args, "confluence_permissions") + discovered_inputs["confluence_permissions"]),
        "zendesk": _unique_paths(_arg_list(args, "zendesk_permissions") + discovered_inputs["zendesk_permissions"]),
        "servicenow": _unique_paths(_arg_list(args, "servicenow_permissions") + discovered_inputs["servicenow_permissions"]),
        "snowflake": _unique_paths(_arg_list(args, "snowflake_grants") + discovered_inputs["snowflake_grants"]),
        "databricks": _unique_paths(_arg_list(args, "databricks_permissions") + discovered_inputs["databricks_permissions"]),
        "stripe": _unique_paths(_arg_list(args, "stripe_permissions") + discovered_inputs["stripe_permissions"]),
        "netsuite": _unique_paths(_arg_list(args, "netsuite_permissions") + discovered_inputs["netsuite_permissions"]),
    }
    runtime_export_paths = {
        "agent_trace": _unique_paths(_arg_list(args, "agent_trace_export") + discovered_inputs["agent_trace_export"]),
        "approval_broker": _unique_paths(_arg_list(args, "approval_broker_export") + discovered_inputs["approval_broker_export"]),
        "mcp_host": _unique_paths(_arg_list(args, "mcp_host_log") + discovered_inputs["mcp_host_log"]),
        "ci_system": _unique_paths(_arg_list(args, "ci_system_log") + discovered_inputs["ci_system_log"]),
        "cloud_audit": _unique_paths(_arg_list(args, "cloud_audit_log") + discovered_inputs["cloud_audit_log"]),
    }
    policy_evaluation_paths = {
        "opa_rego": _unique_paths(_arg_list(args, "opa_policy") + _arg_list(args, "rego_policy") + _arg_list(args, "opa_eval") + discovered_inputs["opa_rego_policy"]),
        "cedar": _unique_paths(_arg_list(args, "cedar_policy") + _arg_list(args, "cedar_eval") + discovered_inputs["cedar_policy"]),
    }
    langgraph_configs = []
    collected_agent_hints: list[dict[str, Any]] = []
    manifest_input_sources: list[dict[str, str]] = []
    collected_identities: list[dict[str, Any]] = []
    collected_data_sources: list[dict[str, Any]] = []
    collected_runtime_events: list[dict[str, Any]] = []
    collected_policy_evaluations: list[dict[str, Any]] = []
    imported_policies: list[dict[str, Any]] = []
    framework_summaries: list[dict[str, Any]] = []

    for config_path in mcp_config_paths:
        converted = parse_mcp_client_config(config_path)
        mcp_servers.extend(converted["servers"])
        warnings.extend(converted.get("warnings", []))
        for server in converted["servers"]:
            for tool in server.get("tools", []):
                if tool.get("name"):
                    tool_ids.add(str(tool["name"]))

    for config_path in openclaw_config_paths:
        converted = parse_openclaw_config(config_path)
        warnings.extend(converted.get("warnings", []))
        if converted.get("tools"):
            mcp_servers.append(
                {
                    "id": f"openclaw:{Path(config_path).stem}",
                    "name": f"OpenClaw local config {Path(config_path).name}",
                    "transport": "local_config",
                    "auth": "unknown",
                    "tools": converted["tools"],
                }
            )
            tool_ids.update(str(tool["name"]) for tool in converted["tools"] if tool.get("name"))
        collected_agent_hints.extend(converted.get("agents", []))
        manifest_input_sources.extend(converted.get("input_sources", []))

    for manifest_path in tool_manifest_paths:
        converted = parse_tool_manifest(manifest_path)
        warnings.extend(converted.get("warnings", []))
        if converted.get("tools"):
            mcp_servers.append(
                {
                    "id": f"manifest:{Path(manifest_path).stem}",
                    "name": f"Local tool manifest {Path(manifest_path).name}",
                    "transport": "local_manifest",
                    "auth": "unknown",
                    "tools": converted["tools"],
                }
            )
            tool_ids.update(str(tool["name"]) for tool in converted["tools"] if tool.get("name"))
        collected_agent_hints.extend(converted.get("agents", []))
        manifest_input_sources.extend(converted.get("input_sources", []))

    for copilot_path in copilot_paths:
        converted = parse_copilot_agent(copilot_path)
        warnings.extend(converted.get("warnings", []))
        mcp_servers.extend(converted.get("mcp_servers", []))
        for server in converted.get("mcp_servers", []):
            tool_ids.update(str(tool["name"]) for tool in server.get("tools", []) if tool.get("name"))
        collected_agent_hints.extend(converted.get("agents", []))
        manifest_input_sources.extend(converted.get("input_sources", []))
        collected_identities.extend(converted.get("identities", []))
        collected_data_sources.extend(converted.get("data_sources", []))
        openapi_paths.extend(converted.get("openapi_paths", []))
    openapi_paths = _unique_paths(openapi_paths)

    for framework_path in framework_code_paths:
        converted = parse_framework_code(framework_path)
        warnings.extend(converted.get("warnings", []))
        framework_summaries.append(
            {
                "source_file": converted.get("source_file", ""),
                "frameworks": converted.get("frameworks", []),
                "agents": [agent.get("id") for agent in converted.get("agents", []) if agent.get("id")],
                "tools": [tool.get("name") for tool in converted.get("tools", []) if tool.get("name")],
            }
        )
        for server_id, tools in _framework_tool_groups(converted.get("tools", []), framework_path).items():
            mcp_servers.append(
                {
                    "id": server_id,
                    "name": f"Framework static tool references {Path(framework_path).name}",
                    "transport": "framework_static",
                    "auth": "unknown",
                    "tools": tools,
                }
            )
            tool_ids.update(str(tool["name"]) for tool in tools if tool.get("name"))
        collected_agent_hints.extend(converted.get("agents", []))
        manifest_input_sources.extend(converted.get("input_sources", []))

    copied_openapi: list[str] = []
    for openapi_path in openapi_paths:
        parsed = parse_openapi(openapi_path)
        warnings.extend(parsed.get("warnings", []))
        tool_ids.update(str(tool["id"]) for tool in parsed.get("tools", []) if tool.get("id"))
        copied_openapi.extend(_copy_openapi_inputs(openapi_path, openapi_dir))

    for langgraph_path in langgraph_paths:
        parsed_langgraph = parse_langgraph_config(langgraph_path)
        langgraph_configs.append(parsed_langgraph)
        warnings.extend(parsed_langgraph.get("warnings", []))

    imported_identities: list[dict[str, Any]] = []
    for export_kind, export_paths in identity_export_paths.items():
        for export_path in export_paths:
            converted = _parse_identity_export(export_kind, export_path)
            imported_identities.extend(converted.get("identities", []))
            warnings.extend(converted.get("warnings", []))

    data_import_summaries: list[dict[str, Any]] = []
    for export_kind, export_paths in data_classification_paths.items():
        for export_path in export_paths:
            converted = _parse_data_classification_export(export_kind, export_path)
            collected_data_sources.extend(converted.get("data_sources", []))
            warnings.extend(converted.get("warnings", []))
            data_import_summaries.append(
                {
                    "kind": converted.get("kind", export_kind),
                    "source_file": converted.get("source_file", export_path),
                    "data_sources": len(converted.get("data_sources", [])),
                }
            )

    runtime_import_summaries: list[dict[str, Any]] = []
    for export_kind, export_paths in runtime_export_paths.items():
        for export_path in export_paths:
            converted = _parse_runtime_event_export(export_kind, export_path)
            collected_runtime_events.extend(converted.get("events", []))
            warnings.extend(converted.get("warnings", []))
            runtime_import_summaries.append(
                {
                    "kind": converted.get("kind", export_kind),
                    "source_file": converted.get("source_file", export_path),
                    "events": len(converted.get("events", [])),
                }
            )

    policy_import_summaries: list[dict[str, Any]] = []
    for export_kind, export_paths in policy_evaluation_paths.items():
        for export_path in export_paths:
            converted = _parse_policy_evaluation_export(export_kind, export_path)
            imported_policies.extend(converted.get("policies", []))
            collected_policy_evaluations.extend(converted.get("policy_evaluations", []))
            warnings.extend(converted.get("warnings", []))
            policy_import_summaries.append(
                {
                    "kind": converted.get("kind", export_kind),
                    "source_file": converted.get("source_file", export_path),
                    "policies": len(converted.get("policies", [])),
                    "policy_evaluations": len(converted.get("policy_evaluations", [])),
                }
            )

    cli_tool_ids = set(_arg_list(args, "tool"))
    tool_ids.update(cli_tool_ids)
    input_sources = _dedupe_input_sources(
        [_parse_input_source(value) for value in _arg_list(args, "input_source")] + manifest_input_sources
    )
    identities = _dedupe_identities(
        [_parse_identity_ref(value) for value in _arg_list(args, "identity")] + imported_identities + collected_identities
    )
    agent_id = _arg_value(args, "agent_id") or _default_collected_agent_id(project_dir, langgraph_configs, collected_agent_hints)
    matching_agent_hint = _select_agent_hint(agent_id, collected_agent_hints)
    if matching_agent_hint:
        tool_ids.update(matching_agent_hint.get("tools", []))
        input_sources = _dedupe_input_sources(
            input_sources + [{"id": source_id, "trust": "unknown", "description": ""} for source_id in matching_agent_hint.get("input_sources", [])]
        )
        identities = _dedupe_identities(
            identities + [_parse_identity_ref(identity_id) for identity_id in matching_agent_hint.get("identities", [])]
        )
    tool_identity_bindings = [
        _parse_tool_identity_binding(value, agent_id)
        for value in _arg_list(args, "tool_identity_binding")
    ]
    if tool_identity_bindings:
        tool_ids.update(binding["tool"] for binding in tool_identity_bindings)
        bound_identity_ids = {binding["identity"] for binding in tool_identity_bindings}
        existing_identity_ids = {identity.get("id") for identity in identities}
        identities = _dedupe_identities(
            identities + [_parse_identity_ref(identity_id) for identity_id in sorted(bound_identity_ids - existing_identity_ids)]
        )
    policy_id = (
        _arg_value(args, "approval_policy_id")
        or (imported_policies[0].get("id") if imported_policies else "")
        or f"{agent_id}-policy"
    )
    labels = {"collector": "local_config"}
    graph_ids = [graph["id"] for config in langgraph_configs for graph in config.get("graphs", []) if graph.get("id")]
    if graph_ids:
        labels["langgraph_graphs"] = ",".join(sorted(set(graph_ids)))
    if matching_agent_hint and isinstance(matching_agent_hint.get("labels"), dict):
        labels.update(matching_agent_hint["labels"])
    runtime = _arg_value(args, "runtime", "unknown")
    environment = _arg_value(args, "environment", "unknown")
    autonomy = _arg_value(args, "autonomy", "unknown")

    _write_json(
        output_dir / "agentguard.json",
        {
            "schema_version": "0.1",
            "agents": [
                {
                    "id": agent_id,
                    "name": _arg_value(args, "agent_name") or agent_id,
                    "owner": _arg_value(args, "owner", ""),
                    "runtime": runtime if runtime != "unknown" else (matching_agent_hint or {}).get("runtime", "unknown"),
                    "environment": environment if environment != "unknown" else (matching_agent_hint or {}).get("environment", "unknown"),
                    "autonomy": autonomy if autonomy != "unknown" else (matching_agent_hint or {}).get("autonomy", "unknown"),
                    "input_sources": [item["id"] for item in input_sources],
                    "tools": sorted(tool_ids),
                    "identities": [item["id"] for item in identities],
                    "tool_identity_bindings": tool_identity_bindings,
                    "memory": [],
                    "approval_policy": policy_id,
                    "labels": labels,
                }
            ],
            "input_sources": input_sources,
            "memory_stores": [],
        },
    )
    deduped_servers = _dedupe_servers(mcp_servers)
    _write_json(output_dir / "mcp-servers.json", {"schema_version": "0.1", "servers": deduped_servers})
    _write_json(output_dir / "identity.json", {"schema_version": "0.1", "identities": identities})
    _write_json(output_dir / "data-catalog.json", {"schema_version": "0.1", "data_sources": _dedupe_data_sources(collected_data_sources)})
    policies = _merge_policies([{"id": policy_id, "rules": []}] + imported_policies)
    _write_json(
        output_dir / "approval-policy.json",
        {
            "schema_version": "0.1",
            "policies": policies,
            "policy_evaluations": collected_policy_evaluations,
        },
    )
    _write_jsonl(output_dir / "events.jsonl", collected_runtime_events)

    generated_files = [
        "agentguard.json",
        "mcp-servers.json",
        "identity.json",
        "data-catalog.json",
        "approval-policy.json",
        "events.jsonl",
    ]
    if copied_openapi:
        generated_files.extend(copied_openapi)
    if not tool_ids:
        warnings.append("No tool descriptors were collected. Provide MCP tools, OpenAPI JSON, or --tool entries before scanning.")
    summary = {
        "schema_version": "0.1",
        "collector": "local_config",
        "discovered_inputs": discovered_inputs,
        "generated_files": generated_files,
        "langgraph": langgraph_configs,
        "copilot": copilot_paths,
        "framework_code": framework_summaries,
        "data_classification_imports": data_import_summaries,
        "runtime_event_imports": runtime_import_summaries,
        "policy_evaluation_imports": policy_import_summaries,
        "agent_hints": collected_agent_hints,
        "tool_identity_bindings": tool_identity_bindings,
        "warnings": warnings,
        "next_steps": [
            "Review generated evidence before scanning.",
            "Add identity permissions and data classifications from admin exports.",
            "Use docs/PERMISSION_TARGETS.md to choose the next target-system exports.",
            "Run agentguard-graph validate --json against the generated evidence pack.",
            "Run agentguard-graph scan with --openapi agent-evidence/openapi if OpenAPI files were collected.",
        ],
    }
    _write_json(output_dir / "collector-summary.json", summary)
    generated_files.append("collector-summary.json")
    write_evidence_manifest(output_dir, generated_files)
    print(f"collected evidence pack: {output_dir}")
    print(
        "evidence summary: "
        f"agents=1 tools={len(tool_ids)} servers={len(deduped_servers)} "
        f"openapi_files={len(copied_openapi)} bindings={len(tool_identity_bindings)} "
        f"data_sources={len(_dedupe_data_sources(collected_data_sources))} "
        f"runtime_events={len(collected_runtime_events)} "
        f"policy_evaluations={len(collected_policy_evaluations)} warnings={len(warnings)}"
    )
    for warning in warnings:
        print(f"warning: {warning}")
    return 0


def _discover_project_inputs(project_dir: str | None) -> dict[str, list[str]]:
    discovered = {
        "mcp_config": [],
        "openapi": [],
        "langgraph_config": [],
        "copilot_agent": [],
        "framework_code": [],
        "data_catalog_export": [],
        "dlp_export": [],
        "sensitivity_label_export": [],
        "table_classification_export": [],
        "openclaw_config": [],
        "tool_manifest": [],
        "github_app_export": [],
        "oauth_scopes_export": [],
        "salesforce_permissions_export": [],
        "aws_iam_policy": [],
        "kubernetes_rbac": [],
        "microsoft_365_permissions": [],
        "azure_rbac": [],
        "gcp_iam_policy": [],
        "dataverse_permissions": [],
        "power_platform_permissions": [],
        "okta_permissions": [],
        "jira_permissions": [],
        "confluence_permissions": [],
        "zendesk_permissions": [],
        "servicenow_permissions": [],
        "snowflake_grants": [],
        "databricks_permissions": [],
        "stripe_permissions": [],
        "netsuite_permissions": [],
        "agent_trace_export": [],
        "approval_broker_export": [],
        "mcp_host_log": [],
        "ci_system_log": [],
        "cloud_audit_log": [],
        "opa_rego_policy": [],
        "cedar_policy": [],
    }
    if not project_dir:
        return discovered
    root = Path(project_dir)
    if not root.exists() or not root.is_dir():
        raise EvidenceLoadError(f"{root}: project directory not found")
    for relative in [
        ".mcp.json",
        ".claude/mcp_servers.json",
        ".cursor/mcp.json",
        "claude_desktop_config.json",
        "mcp.json",
    ]:
        path = root / relative
        if path.exists():
            discovered["mcp_config"].append(str(path))
    for relative in ["openclaw.json", ".openclaw/openclaw.json"]:
        path = root / relative
        if path.exists():
            discovered["openclaw_config"].append(str(path))
    for relative in [
        "agentguard-tools.json",
        "langchain-tools.json",
        "agent-tools.json",
        "tools.json",
    ]:
        path = root / relative
        if path.exists():
            discovered["tool_manifest"].append(str(path))
    for relative in ["langgraph.json", "langgraph.config.json"]:
        path = root / relative
        if path.exists():
            discovered["langgraph_config"].append(str(path))
    app_package_manifest = root / "appPackage" / "manifest.json"
    if app_package_manifest.exists():
        discovered["copilot_agent"].append(str(app_package_manifest))
    else:
        for relative in [
            "manifest.json",
            "appPackage/declarativeAgent.json",
            "declarativeAgent.json",
            "declarative-agent.json",
            "copilot-agent.json",
        ]:
            path = root / relative
            if path.exists():
                discovered["copilot_agent"].append(str(path))
    for relative in ["copilot-agent.zip", "appPackage.zip"]:
        path = root / relative
        if path.exists():
            discovered["copilot_agent"].append(str(path))
    for relative in [
        "openapi.json",
        "swagger.json",
        "api/openapi.json",
        "docs/openapi.json",
        "openapi",
        "api-specs",
    ]:
        path = root / relative
        if path.exists():
            discovered["openapi"].append(str(path))
    for key, relatives in {
        "github_app_export": ["github-app-permissions.json", "github-app.json"],
        "data_catalog_export": ["data-catalog-export.json", "collibra-assets.json", "purview-assets.json", "datahub-assets.json"],
        "dlp_export": ["dlp-findings.json", "dlp-export.json", "sensitive-data-findings.json"],
        "sensitivity_label_export": ["sensitivity-labels.json", "mip-labels.json", "purview-labels.json"],
        "table_classification_export": ["table-classifications.json", "object-classifications.json", "column-classifications.json"],
        "oauth_scopes_export": ["oauth-scopes.json", "slack-oauth-scopes.json", "google-oauth-scopes.json"],
        "salesforce_permissions_export": ["salesforce-permissions.json", "salesforce-object-permissions.json"],
        "aws_iam_policy": ["aws-iam-policy.json", "iam-policy.json"],
        "kubernetes_rbac": ["kubernetes-rbac.json", "k8s-rbac.json", "rbac.json"],
        "microsoft_365_permissions": ["microsoft-365-permissions.json", "m365-permissions.json", "graph-permissions.json"],
        "azure_rbac": ["azure-rbac.json", "azure-role-assignments.json"],
        "gcp_iam_policy": ["gcp-iam-policy.json", "google-cloud-iam-policy.json"],
        "dataverse_permissions": ["dataverse-permissions.json", "dataverse-roles.json"],
        "power_platform_permissions": ["power-platform-permissions.json", "powerplatform-permissions.json"],
        "okta_permissions": ["okta-permissions.json", "okta-admin-roles.json"],
        "jira_permissions": ["jira-permissions.json", "jira-project-permissions.json"],
        "confluence_permissions": ["confluence-permissions.json", "confluence-space-permissions.json"],
        "zendesk_permissions": ["zendesk-permissions.json", "zendesk-role-permissions.json"],
        "servicenow_permissions": ["servicenow-permissions.json", "servicenow-acl-permissions.json"],
        "snowflake_grants": ["snowflake-grants.json", "snowflake-permissions.json"],
        "databricks_permissions": ["databricks-permissions.json", "databricks-object-permissions.json"],
        "stripe_permissions": ["stripe-permissions.json", "stripe-restricted-key.json"],
        "netsuite_permissions": ["netsuite-permissions.json", "netsuite-role-permissions.json"],
        "agent_trace_export": ["agent-traces.json", "agent-trace-export.json", "runtime-traces.json"],
        "approval_broker_export": ["approval-broker.json", "approvals.json", "approval-decisions.json"],
        "mcp_host_log": ["mcp-host-log.json", "mcp-tool-calls.json", "mcp-runtime-events.json"],
        "ci_system_log": ["ci-runs.json", "ci-events.json", "github-actions-runs.json"],
        "cloud_audit_log": ["cloud-audit-log.json", "aws-cloudtrail.json", "gcp-audit-log.json", "azure-activity-log.json"],
        "opa_rego_policy": [
            "policy.rego",
            "approval-policy.rego",
            "agentguard.rego",
            "opa-eval.json",
            "opa-decision-log.json",
        ],
        "cedar_policy": [
            "policy.cedar",
            "approval-policy.cedar",
            "agentguard.cedar",
            "cedar-authorize.json",
            "cedar-eval.json",
        ],
    }.items():
        for relative in relatives:
            path = root / relative
            if path.exists():
                discovered[key].append(str(path))
    if _project_declares_agent_framework(root):
        discovered["framework_code"].append(str(root))
    discovered["framework_code"] = _unique_paths(discovered["framework_code"])
    return discovered


def _project_declares_agent_framework(root: Path) -> bool:
    if (root / "config" / "agents.yaml").exists() or (root / "config" / "tasks.yaml").exists():
        return True
    for package_config in root.glob("src/*/config/agents.yaml"):
        if package_config.exists():
            return True
    dependency_files = [
        "pyproject.toml",
        "requirements.txt",
        "requirements-dev.txt",
        "uv.lock",
        "poetry.lock",
        "Pipfile",
        "Pipfile.lock",
        "setup.cfg",
        "setup.py",
        "environment.yml",
    ]
    dependency_text = []
    for relative in dependency_files:
        path = root / relative
        if not path.exists() or not path.is_file():
            continue
        try:
            dependency_text.append(path.read_text(encoding="utf-8", errors="ignore")[:250_000].lower())
        except OSError:
            continue
    text = "\n".join(dependency_text)
    if not text:
        return False
    hints = sorted({hint.lower() for spec in TOP_AGENT_FRAMEWORKS for hint in spec.dependency_hints if hint})
    return any(_dependency_hint_present(text, hint) for hint in hints)


def _dependency_hint_present(text: str, hint: str) -> bool:
    package = re.escape(hint.lower())
    return re.search(rf"(?<![a-z0-9_.-]){package}(?![a-z0-9_.-])", text) is not None


def _unique_paths(paths: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for path in paths:
        normalized = str(Path(path))
        if normalized in seen:
            continue
        seen.add(normalized)
        unique.append(normalized)
    return unique


def _arg_list(args: argparse.Namespace, name: str) -> list[str]:
    value = getattr(args, name, None)
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return [str(value)]


def _arg_value(args: argparse.Namespace, name: str, default: Any = None) -> Any:
    return getattr(args, name, default)


def _framework_tool_groups(tools: list[dict[str, Any]], framework_path: str) -> dict[str, list[dict[str, Any]]]:
    fallback_id = f"framework-code:{Path(framework_path).stem or Path(framework_path).name or 'project'}"
    grouped: dict[str, list[dict[str, Any]]] = {}
    for tool in tools:
        server_id = str(tool.get("server_id") or fallback_id)
        grouped.setdefault(server_id, []).append(tool)
    return grouped


def _default_collected_agent_id(
    project_dir: str | None,
    langgraph_configs: list[dict[str, Any]],
    agent_hints: list[dict[str, Any]] | None = None,
) -> str:
    hint_ids = sorted(set(hint["id"] for hint in agent_hints or [] if hint.get("id")))
    if len(hint_ids) == 1:
        return hint_ids[0]
    graph_ids = [graph["id"] for config in langgraph_configs for graph in config.get("graphs", []) if graph.get("id")]
    if len(graph_ids) == 1:
        return graph_ids[0]
    if project_dir:
        return Path(project_dir).resolve().name or "collected-agent"
    return "collected-agent"


def _select_agent_hint(agent_id: str, agent_hints: list[dict[str, Any]]) -> dict[str, Any] | None:
    for hint in agent_hints:
        if hint.get("id") == agent_id:
            return hint
    if len(agent_hints) == 1:
        return agent_hints[0]
    return None


def _dedupe_input_sources(input_sources: list[dict[str, str]]) -> list[dict[str, str]]:
    deduped: dict[str, dict[str, str]] = {}
    for input_source in input_sources:
        source_id = input_source.get("id", "")
        if not source_id:
            continue
        if source_id not in deduped:
            deduped[source_id] = input_source
            continue
        if deduped[source_id].get("trust") in {"", "unknown"} and input_source.get("trust"):
            deduped[source_id]["trust"] = input_source["trust"]
        if not deduped[source_id].get("description") and input_source.get("description"):
            deduped[source_id]["description"] = input_source["description"]
    return list(deduped.values())


def _ensure_output_dir(path: str | Path, label: str) -> Path:
    output_dir = Path(path)
    if output_dir.exists() and not output_dir.is_dir():
        raise EvidenceLoadError(f"{output_dir}: {label} exists but is not a directory")
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise EvidenceLoadError(f"{output_dir}: cannot create {label}: {exc}") from exc
    return output_dir


def _write_json(path: Path, data: dict[str, Any]) -> None:
    _write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    _write_text(path, "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))


def _write_text(path: Path, content: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise EvidenceLoadError(f"{path}: cannot write file: {exc}") from exc


def _write_bytes(path: Path, content: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    except OSError as exc:
        raise EvidenceLoadError(f"{path}: cannot write file: {exc}") from exc


def _parse_input_source(value: str) -> dict[str, str]:
    parts = value.split(":", 2)
    source_id = parts[0]
    trust = parts[1] if len(parts) > 1 else "unknown"
    description = parts[2] if len(parts) > 2 else ""
    if not source_id:
        raise EvidenceLoadError("--input-source must start with a non-empty id, for example pull_request_comment:untrusted")
    if trust not in TRUST_VALUES:
        raise EvidenceLoadError(
            f"--input-source {source_id}: invalid trust value {trust!r}; expected one of {', '.join(sorted(TRUST_VALUES))}"
        )
    return {"id": source_id, "trust": trust, "description": description}


def _parse_identity_ref(value: str) -> dict[str, Any]:
    if "=" in value:
        identity_id, remainder = value.split("=", 1)
        identity_type, _, target_system = remainder.partition(":")
        if not identity_id or not identity_type or not target_system:
            raise EvidenceLoadError("--identity with '=' must use id=type:target_system, for example github:app=github_app:github")
    else:
        identity_id = value
        identity_type = "unknown"
        target_system = infer_target_system(value)
        if not identity_id:
            raise EvidenceLoadError("--identity must be a non-empty id")
    return {
        "id": identity_id,
        "type": identity_type or "unknown",
        "target_system": target_system or infer_target_system(identity_id),
        "permissions": [],
    }


def _parse_tool_identity_binding(value: str, agent_id: str) -> dict[str, str]:
    tool_id, separator, identity_id = value.partition("=")
    tool_id = tool_id.strip()
    identity_id = identity_id.strip()
    if not separator or not tool_id or not identity_id:
        raise EvidenceLoadError(
            "--tool-identity-binding must use TOOL=IDENTITY, for example github.create_pr=github:code-agent"
        )
    return {"agent": agent_id, "tool": tool_id, "identity": identity_id}


def _parse_identity_export(export_kind: str, path: str) -> dict[str, Any]:
    if export_kind == "github_app":
        return parse_github_app_export(path)
    if export_kind == "oauth_scopes":
        return parse_oauth_scope_export(path)
    if export_kind == "salesforce":
        return parse_salesforce_permissions_export(path)
    if export_kind == "aws_iam":
        return parse_aws_iam_policy_export(path)
    if export_kind == "kubernetes_rbac":
        return parse_kubernetes_rbac_export(path)
    if export_kind == "microsoft_365":
        return parse_microsoft_365_permission_export(path)
    if export_kind == "azure_rbac":
        return parse_azure_rbac_export(path)
    if export_kind == "gcp_iam":
        return parse_gcp_iam_policy_export(path)
    if export_kind == "dataverse":
        return parse_dataverse_permissions_export(path)
    if export_kind == "power_platform":
        return parse_power_platform_permissions_export(path)
    if export_kind == "okta":
        return parse_okta_permissions_export(path)
    if export_kind == "jira":
        return parse_jira_permissions_export(path)
    if export_kind == "confluence":
        return parse_confluence_permissions_export(path)
    if export_kind == "zendesk":
        return parse_zendesk_permissions_export(path)
    if export_kind == "servicenow":
        return parse_servicenow_permissions_export(path)
    if export_kind == "snowflake":
        return parse_snowflake_grants_export(path)
    if export_kind == "databricks":
        return parse_databricks_permissions_export(path)
    if export_kind == "stripe":
        return parse_stripe_permissions_export(path)
    if export_kind == "netsuite":
        return parse_netsuite_permissions_export(path)
    raise EvidenceLoadError(f"unsupported identity export kind: {export_kind}")


def _parse_runtime_event_export(export_kind: str, path: str) -> dict[str, Any]:
    if export_kind == "agent_trace":
        return parse_agent_trace_export(path)
    if export_kind == "approval_broker":
        return parse_approval_broker_export(path)
    if export_kind == "mcp_host":
        return parse_mcp_host_log(path)
    if export_kind == "ci_system":
        return parse_ci_system_log(path)
    if export_kind == "cloud_audit":
        return parse_cloud_audit_log(path)
    raise EvidenceLoadError(f"unsupported runtime export kind: {export_kind}")


def _parse_data_classification_export(export_kind: str, path: str) -> dict[str, Any]:
    if export_kind == "data_catalog":
        return parse_data_catalog_export(path)
    if export_kind == "dlp":
        return parse_dlp_export(path)
    if export_kind == "sensitivity_label":
        return parse_sensitivity_label_export(path)
    if export_kind == "table_classification":
        return parse_table_classification_export(path)
    raise EvidenceLoadError(f"unsupported data classification export kind: {export_kind}")


def _parse_policy_evaluation_export(export_kind: str, path: str) -> dict[str, Any]:
    if export_kind == "opa_rego":
        return parse_opa_policy(path)
    if export_kind == "cedar":
        return parse_cedar_policy(path)
    raise EvidenceLoadError(f"unsupported policy evaluation export kind: {export_kind}")


def _merge_policies(policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for policy in policies:
        policy_id = str(policy.get("id") or "")
        if not policy_id:
            continue
        if policy_id not in merged:
            merged[policy_id] = {**policy, "rules": list(policy.get("rules", []))}
            continue
        existing = merged[policy_id]
        if not existing.get("engine") and policy.get("engine"):
            existing["engine"] = policy["engine"]
        if existing.get("source_file") in {"", "unknown", None} and policy.get("source_file"):
            existing["source_file"] = policy["source_file"]
        known_rules = {rule.get("id") for rule in existing.get("rules", []) if isinstance(rule, dict)}
        for rule in policy.get("rules", []):
            if not isinstance(rule, dict):
                continue
            if rule.get("id") not in known_rules:
                existing.setdefault("rules", []).append(rule)
                known_rules.add(rule.get("id"))
    return list(merged.values())


def _dedupe_identities(identities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for identity in identities:
        identity_id = identity.get("id", "")
        if not identity_id:
            continue
        if identity_id not in deduped:
            deduped[identity_id] = identity
            continue
        existing = deduped[identity_id]
        if existing.get("type") in {"", "unknown"} and identity.get("type"):
            existing["type"] = identity["type"]
        if existing.get("target_system") in {"", "unknown"} and identity.get("target_system"):
            existing["target_system"] = identity["target_system"]
        existing["scopes"] = sorted(set(existing.get("scopes", []) + identity.get("scopes", [])))
        existing_permissions = {
            (
                permission.get("resource"),
                tuple(permission.get("actions", [])),
                tuple(permission.get("data_classes", [])),
            )
            for permission in existing.get("permissions", [])
        }
        for permission in identity.get("permissions", []):
            key = (
                permission.get("resource"),
                tuple(permission.get("actions", [])),
                tuple(permission.get("data_classes", [])),
            )
            if key not in existing_permissions:
                existing.setdefault("permissions", []).append(permission)
                existing_permissions.add(key)
        if existing.get("confidence") in {"", "low", "medium"} and identity.get("confidence") == "high":
            existing["confidence"] = "high"
    return list(deduped.values())


def _dedupe_data_sources(data_sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for data_source in data_sources:
        data_id = data_source.get("id", "")
        if not data_id:
            continue
        if data_id not in deduped:
            deduped[data_id] = data_source
            continue
        existing = deduped[data_id]
        if existing.get("sensitivity") in {"", "unknown"} and data_source.get("sensitivity"):
            existing["sensitivity"] = data_source["sensitivity"]
        if existing.get("target_system") in {"", "unknown"} and data_source.get("target_system"):
            existing["target_system"] = data_source["target_system"]
        if not existing.get("owner") and data_source.get("owner"):
            existing["owner"] = data_source["owner"]
        if existing.get("persistence") in {"", "unknown"} and data_source.get("persistence"):
            existing["persistence"] = data_source["persistence"]
        for list_field in ["classification_labels", "fields"]:
            existing[list_field] = _dedupe_unhashable(existing.get(list_field, []) + data_source.get(list_field, []))
        for scalar_field in ["source_kind", "source_evidence"]:
            values = sorted(set(existing.get(f"{scalar_field}s", []) + [value for value in [existing.get(scalar_field), data_source.get(scalar_field)] if value]))
            if values:
                existing[f"{scalar_field}s"] = values
        existing["data_classes"] = sorted(set(existing.get("data_classes", []) + data_source.get("data_classes", [])))
    return list(deduped.values())


def _dedupe_unhashable(values: list[Any]) -> list[Any]:
    deduped: list[Any] = []
    seen: set[str] = set()
    for value in values:
        key = json.dumps(value, sort_keys=True, default=str)
        if key in seen:
            continue
        deduped.append(value)
        seen.add(key)
    return deduped


def _copy_openapi_inputs(openapi_path: str, output_dir: Path) -> list[str]:
    source = Path(openapi_path)
    if not source.exists():
        return []
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise EvidenceLoadError(f"{output_dir}: cannot create OpenAPI output directory: {exc}") from exc
    copied: list[str] = []
    files_to_copy = sorted(source.glob("*.json")) if source.is_dir() else [source]
    for file_path in files_to_copy:
        if file_path.suffix.lower() != ".json":
            continue
        destination = output_dir / file_path.name
        try:
            shutil.copyfile(file_path, destination)
        except OSError as exc:
            raise EvidenceLoadError(f"{destination}: cannot copy OpenAPI evidence from {file_path}: {exc}") from exc
        copied.append(str(Path("openapi") / file_path.name))
    return copied


def _dedupe_servers(servers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for server in servers:
        server_id = server.get("id", "")
        if not server_id:
            continue
        if server_id not in deduped:
            deduped[server_id] = server
            continue
        known_tools = {tool.get("name") for tool in deduped[server_id].get("tools", [])}
        for tool in server.get("tools", []):
            if tool.get("name") not in known_tools:
                deduped[server_id].setdefault("tools", []).append(tool)
    return list(deduped.values())


def _sample_file_payloads(sample_name: str) -> list[tuple[str, bytes]]:
    candidates = [Path.cwd() / "samples" / sample_name]
    candidates.extend(parent / "samples" / sample_name for parent in Path(__file__).resolve().parents)
    for sample_dir in candidates:
        if not sample_dir.exists():
            continue
        return [(sample_file.name, sample_file.read_bytes()) for sample_file in sorted(sample_dir.iterdir()) if sample_file.is_file()]
    package_dir = files("agentguard_graph").joinpath("sample_packs", sample_name)
    if package_dir.is_dir():
        return [(sample_file.name, sample_file.read_bytes()) for sample_file in sorted(package_dir.iterdir(), key=lambda item: item.name) if sample_file.is_file()]
    return []


def cmd_demo(args: argparse.Namespace) -> int:
    output_dir = _ensure_output_dir(Path("outputs") / "demo", "demo output directory")
    with TemporaryDirectory() as tmp:
        sample_dir = Path(tmp)
        for file_name, payload in _sample_file_payloads("demo-enterprise"):
            _write_bytes(sample_dir / file_name, payload)
        scan_args = argparse.Namespace(
            agents=str(sample_dir / "agentguard.json"),
            mcp=str(sample_dir / "mcp-servers.json"),
            openapi=None,
            identity=str(sample_dir / "identity.json"),
            data_catalog=str(sample_dir / "data-catalog.json"),
            approval_policy=str(sample_dir / "approval-policy.json"),
            events=str(sample_dir / "events.jsonl"),
            out=str(output_dir / "agent-risk.json"),
            markdown=str(output_dir / "agent-risk.md"),
            html=str(output_dir / "agent-risk.html"),
        )
        code = cmd_scan(scan_args)
        if code != 0:
            return code
        inventory_args = argparse.Namespace(
            agents=scan_args.agents,
            mcp=scan_args.mcp,
            openapi=None,
            identity=scan_args.identity,
            data_catalog=scan_args.data_catalog,
            approval_policy=scan_args.approval_policy,
            events=scan_args.events,
            out=str(output_dir / "inventory.json"),
        )
        return cmd_inventory(inventory_args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentguard-graph", description="Build an agent security graph from evidence.")
    parser.add_argument("--version", action="version", version=f"agentguard-graph {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Build graph, analyze paths, and write reports.")
    add_evidence_args(scan)
    scan.add_argument("--out", required=True, help="JSON report output path")
    scan.add_argument("--markdown", help="Markdown report output path")
    scan.add_argument("--html", help="Self-contained HTML report output path")
    scan.set_defaults(func=cmd_scan)

    inventory = subparsers.add_parser("inventory", help="Write inventory and graph facts without attack-path scoring.")
    add_evidence_args(inventory, include_policy=True, include_events=False)
    inventory.add_argument("--out", required=True, help="Inventory JSON output path")
    inventory.set_defaults(func=cmd_inventory)

    explain = subparsers.add_parser("explain", help="Explain one finding/path from a saved report.")
    explain.add_argument("--findings", required=True, help="Saved JSON report")
    explain.add_argument("--path-id", required=True, help="Attack path id to explain")
    explain.set_defaults(func=cmd_explain)

    compare = subparsers.add_parser("compare", help="Compare two saved JSON reports or evidence pack directories.")
    compare.add_argument("--base", required=True, help="Base JSON report path or evidence pack directory")
    compare.add_argument("--head", required=True, help="Head JSON report path or evidence pack directory")
    compare.add_argument("--base-label", help="Human-readable base label")
    compare.add_argument("--head-label", help="Human-readable head label")
    compare.add_argument("--out", required=True, help="JSON comparison output path")
    compare.add_argument("--markdown", help="Markdown comparison output path")
    compare.set_defaults(func=cmd_compare)

    portfolio = subparsers.add_parser("portfolio", help="Roll up a directory of saved JSON risk reports.")
    portfolio.add_argument("--reports-dir", required=True, help="Directory containing AgentGuard JSON risk reports")
    portfolio.add_argument("--out", required=True, help="JSON portfolio output path")
    portfolio.add_argument("--markdown", help="Markdown portfolio output path")
    portfolio.add_argument("--html", help="Self-contained HTML portfolio output path")
    portfolio.add_argument(
        "--recursive",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Search reports-dir recursively. Enabled by default.",
    )
    portfolio.set_defaults(func=cmd_portfolio)

    validate = subparsers.add_parser("validate", help="Validate evidence files.")
    add_evidence_args(validate)
    validate.add_argument("--json", action="store_true", help="Write validation result as JSON.")
    validate.set_defaults(func=cmd_validate)

    doctor = subparsers.add_parser("doctor", help="Check evidence readiness and secret safety before handoff.")
    add_evidence_args(doctor)
    doctor.add_argument("--project-dir", help="Agent project directory to inspect for known local evidence sources")
    doctor.add_argument("--out", help="Write doctor report JSON to this path")
    doctor.add_argument("--json", action="store_true", help="Write doctor result as JSON.")
    doctor.add_argument(
        "--write-plan",
        nargs="?",
        const=True,
        default=None,
        metavar="PATH",
        help="Write a machine-readable collection plan JSON. Defaults to collection-plan.json in the evidence or project directory.",
    )
    doctor.add_argument(
        "--profile",
        choices=[
            "developer",
            "agent-developer",
            "platform-team",
            "iam-admin",
            "iam_admin",
            "data-owner",
            "data_owner",
            "security-reviewer",
            "security_reviewer",
            "appsec",
        ],
        help="Show the doctor view for one persona.",
    )
    doctor.add_argument(
        "--fail-on-secrets",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Return exit code 3 when likely secrets are found. Enabled by default.",
    )
    doctor.set_defaults(func=cmd_doctor)

    init = subparsers.add_parser("init", help="Create a starter evidence pack.")
    init.add_argument("--out", required=True, help="Output directory")
    init.add_argument(
        "--sample",
        choices=["support-agent", "coding-agent", "demo-enterprise"],
        help="Copy a checked-in sample evidence pack",
    )
    init.set_defaults(func=cmd_init)

    collect = subparsers.add_parser("collect", help="Generate an evidence pack from local read-only config files.")
    collect.add_argument("--out", required=True, help="Output evidence directory")
    collect.add_argument("--project-dir", help="Agent project directory to inspect for known local config files")
    collect.add_argument("--agent-id", help="Agent id to write into agentguard.json")
    collect.add_argument("--agent-name", help="Human-readable agent name")
    collect.add_argument("--owner", help="Agent owner/team")
    collect.add_argument("--runtime", default="unknown", help="Runtime name, for example claude-code, langchain, or custom")
    collect.add_argument("--environment", default="unknown", choices=sorted(ENVIRONMENT_VALUES), help="Agent environment")
    collect.add_argument("--autonomy", default="unknown", choices=sorted(AUTONOMY_VALUES), help="Agent autonomy level")
    collect.add_argument(
        "--input-source",
        action="append",
        help="Input source as id:trust[:description], for example pull_request_comment:untrusted:PR comments",
    )
    collect.add_argument(
        "--identity",
        action="append",
        help="Identity id, or id=type:target_system. Permissions are left empty until an admin export is added.",
    )
    collect.add_argument("--tool", action="append", help="Additional tool name to attach to the agent")
    collect.add_argument(
        "--tool-identity-binding",
        action="append",
        help="Bind a tool to the identity it uses, formatted as TOOL=IDENTITY",
    )
    collect.add_argument("--mcp-config", action="append", help="Local MCP client config JSON to read")
    collect.add_argument("--claude-config", action="append", help="Claude Code/Desktop MCP config JSON such as .mcp.json")
    collect.add_argument("--openclaw-config", action="append", help="OpenClaw JSON config export such as openclaw.json")
    collect.add_argument("--langchain-manifest", action="append", help="Local LangChain/custom tool manifest JSON")
    collect.add_argument("--langgraph-config", action="append", help="LangGraph langgraph.json file to read")
    collect.add_argument("--copilot-agent", action="append", help="Microsoft 365 Copilot app package directory, zip, or manifest JSON")
    collect.add_argument("--framework-code", action="append", help="Python project path to statically scan for common agent frameworks")
    collect.add_argument("--openapi", action="append", help="OpenAPI JSON file or directory to copy and parse for tool ids")
    collect.add_argument("--data-catalog-export", action="append", help="Data catalog JSON export with assets, datasets, tables, or objects")
    collect.add_argument("--dlp-export", action="append", help="DLP JSON export with sensitive data findings")
    collect.add_argument("--sensitivity-label-export", action="append", help="Sensitivity-label JSON export such as Microsoft Purview or MIP labels")
    collect.add_argument("--table-classification-export", action="append", help="Table, column, or object classification JSON export")
    collect.add_argument("--github-app-export", action="append", help="GitHub App permissions JSON export")
    collect.add_argument("--oauth-scopes-export", action="append", help="OAuth scopes JSON export for Slack, Google, Microsoft Graph, GitHub, Jira, Confluence, or Okta")
    collect.add_argument("--salesforce-permissions-export", action="append", help="Salesforce object permissions JSON export")
    collect.add_argument("--aws-iam-policy", action="append", help="AWS IAM policy JSON export")
    collect.add_argument("--kubernetes-rbac", action="append", help="Kubernetes Role/ClusterRole RBAC JSON export")
    collect.add_argument("--microsoft-365-permissions", action="append", help="Microsoft 365/Graph permissions JSON export")
    collect.add_argument("--azure-rbac", action="append", help="Azure RBAC role assignments JSON export")
    collect.add_argument("--gcp-iam-policy", action="append", help="Google Cloud IAM policy JSON export")
    collect.add_argument("--dataverse-permissions", action="append", help="Dataverse table/security-role permissions JSON export")
    collect.add_argument("--power-platform-permissions", action="append", help="Power Platform app/flow/approval permissions JSON export")
    collect.add_argument("--okta-permissions", action="append", help="Okta admin role or app permissions JSON export")
    collect.add_argument("--jira-permissions", action="append", help="Jira project permissions JSON export")
    collect.add_argument("--confluence-permissions", action="append", help="Confluence space permissions JSON export")
    collect.add_argument("--zendesk-permissions", action="append", help="Zendesk role permissions JSON export")
    collect.add_argument("--servicenow-permissions", action="append", help="ServiceNow ACL/table permissions JSON export")
    collect.add_argument("--snowflake-grants", action="append", help="Snowflake grants JSON export")
    collect.add_argument("--databricks-permissions", action="append", help="Databricks object permissions JSON export")
    collect.add_argument("--stripe-permissions", action="append", help="Stripe restricted-key permissions JSON export")
    collect.add_argument("--netsuite-permissions", action="append", help="NetSuite role permissions JSON export")
    collect.add_argument("--agent-trace-export", action="append", help="Agent tracing store JSON export with spans, runs, or events")
    collect.add_argument("--approval-broker-export", action="append", help="Approval broker JSON export with requests or decisions")
    collect.add_argument("--mcp-host-log", action="append", help="MCP host JSON log with tool calls or server requests")
    collect.add_argument("--ci-system-log", action="append", help="CI system JSON export with workflow runs, jobs, or steps")
    collect.add_argument("--cloud-audit-log", action="append", help="Cloud audit JSON export such as CloudTrail, GCP audit logs, or Azure activity logs")
    collect.add_argument("--opa-policy", action="append", help="OPA/Rego policy source or JSON decision export")
    collect.add_argument("--rego-policy", action="append", help="Rego policy source file")
    collect.add_argument("--opa-eval", action="append", help="OPA eval JSON or decision log export")
    collect.add_argument("--cedar-policy", action="append", help="Cedar policy source or authorization result JSON")
    collect.add_argument("--cedar-eval", action="append", help="Cedar authorization result JSON export")
    collect.add_argument("--approval-policy-id", help="Approval policy id to reference from the generated agent")
    collect.set_defaults(func=cmd_collect)

    demo = subparsers.add_parser("demo", help="Run checked-in sample evidence and write outputs/demo.")
    demo.set_defaults(func=cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except AgentGuardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
