import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from _helpers import ROOT
from agentguard_graph.adapters.runtime_exports import (
    parse_agent_trace_export,
    parse_approval_broker_export,
    parse_ci_system_log,
    parse_cloud_audit_log,
    parse_mcp_host_log,
)


def write_json(path: Path, data: object) -> str:
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


class RuntimeExportAdapterTests(unittest.TestCase):
    def test_agent_trace_export_normalizes_spans(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "agent-traces.json"
            result = parse_agent_trace_export(
                write_json(
                    path,
                    {
                        "spans": [
                            {
                                "id": "span-1",
                                "trace_id": "support-1001",
                                "agent": "support-agent",
                                "name": "salesforce.get_contact",
                                "timestamp": "2026-05-18T10:00:00Z",
                                "status": "success",
                            }
                        ]
                    },
                )
            )

        self.assertEqual(result["kind"], "agent_trace")
        event = result["events"][0]
        self.assertEqual(event["event_type"], "agent.tool_call")
        self.assertEqual(event["session_id"], "support-1001")
        self.assertEqual(event["tool"], "salesforce.get_contact")
        self.assertEqual(event["decision"], "allow")

    def test_agent_trace_export_reads_common_span_attributes(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "otel-traces.json"
            result = parse_agent_trace_export(
                write_json(
                    path,
                    {
                        "spans": [
                            {
                                "span_id": "span-2",
                                "timestamp": "2026-05-18T10:01:00Z",
                                "attributes": {
                                    "agent.name": "research-agent",
                                    "session.id": "thread-7",
                                    "tool.name": "slack.search",
                                    "target.system": "slack",
                                },
                            }
                        ]
                    },
                )
            )

        event = result["events"][0]
        self.assertEqual(event["agent"], "research-agent")
        self.assertEqual(event["session_id"], "thread-7")
        self.assertEqual(event["tool"], "slack.search")
        self.assertEqual(event["target"], "slack")

    def test_approval_broker_export_maps_decisions(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "approvals.json"
            result = parse_approval_broker_export(
                write_json(
                    path,
                    {
                        "approvals": [
                            {
                                "approval_id": "ap-1",
                                "requester_agent": "release-agent",
                                "operation": "deploy_production",
                                "created_at": "2026-05-18T10:05:00Z",
                                "status": "approved",
                                "principal": "ops-approver",
                                "policy_id": "prod-change",
                            }
                        ]
                    },
                )
            )

        event = result["events"][0]
        self.assertEqual(event["event_type"], "agent.approval_granted")
        self.assertEqual(event["decision"], "allow")
        self.assertEqual(event["tool"], "deploy_production")
        self.assertEqual(event["identity"], "ops-approver")

    def test_mcp_host_log_prefixes_server_tools(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "mcp-host-log.json"
            result = parse_mcp_host_log(
                write_json(
                    path,
                    {
                        "tool_calls": [
                            {
                                "id": "mcp-1",
                                "client": "coding-agent",
                                "request_id": "req-1",
                                "server": "github",
                                "tool_name": "create_pr",
                                "time": "2026-05-18T10:10:00Z",
                                "status": "blocked",
                            }
                        ]
                    },
                )
            )

        event = result["events"][0]
        self.assertEqual(event["tool"], "github.create_pr")
        self.assertEqual(event["decision"], "blocked")
        self.assertEqual(event["source_kind"], "mcp_host")

    def test_ci_system_log_normalizes_workflow_runs(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "ci-runs.json"
            result = parse_ci_system_log(
                write_json(
                    path,
                    {
                        "workflow_runs": [
                            {
                                "run_id": "run-42",
                                "provider": "github-actions",
                                "workflow_name": "deploy-prod",
                                "repository": "acme/payments",
                                "actor": "release-bot",
                                "created_at": "2026-05-18T10:15:00Z",
                                "conclusion": "success",
                            }
                        ]
                    },
                )
            )

        event = result["events"][0]
        self.assertEqual(event["session_id"], "run-42")
        self.assertEqual(event["tool"], "github-actions.deploy-prod")
        self.assertEqual(event["action_class"], "ci_cd_write")
        self.assertEqual(event["data_classes"], ["source_code"])

    def test_cloud_audit_log_normalizes_cloudtrail_records(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "aws-cloudtrail.json"
            result = parse_cloud_audit_log(
                write_json(
                    path,
                    {
                        "Records": [
                            {
                                "eventID": "evt-1",
                                "requestID": "req-aws-1",
                                "eventTime": "2026-05-18T10:20:00Z",
                                "eventSource": "s3.amazonaws.com",
                                "eventName": "PutObject",
                                "userIdentity": {"arn": "arn:aws:iam::123456789012:role/agent-runtime"},
                                "resource": "arn:aws:s3:::customer-data/export.json",
                            }
                        ]
                    },
                )
            )

        event = result["events"][0]
        self.assertEqual(event["source_kind"], "cloud_audit")
        self.assertEqual(event["target"], "arn:aws:s3:::customer-data/export.json")
        self.assertEqual(event["tool"], "aws.PutObject")
        self.assertEqual(event["decision"], "allow")

    def test_cloud_audit_log_normalizes_gcp_proto_payload_records(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "gcp-audit-log.json"
            result = parse_cloud_audit_log(
                write_json(
                    path,
                    {
                        "protoPayloads": [
                            {
                                "insertId": "gcp-evt-1",
                                "timestamp": "2026-05-18T10:25:00Z",
                                "serviceName": "storage.googleapis.com",
                                "methodName": "storage.objects.create",
                                "authenticationInfo": {"principalEmail": "agent-runtime@example.com"},
                                "resourceName": "projects/_/buckets/customer-data/objects/export.json",
                            }
                        ]
                    },
                )
            )

        event = result["events"][0]
        self.assertEqual(event["source_kind"], "cloud_audit")
        self.assertEqual(event["identity"], "agent-runtime@example.com")
        self.assertEqual(event["session_id"], "gcp-evt-1")
        self.assertEqual(event["tool"], "gcp.storage.objects.create")


if __name__ == "__main__":
    unittest.main()
