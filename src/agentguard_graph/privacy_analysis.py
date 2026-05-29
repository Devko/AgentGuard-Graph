"""Privacy-oriented rollups for data classification and retention evidence."""

from __future__ import annotations

import json
from typing import Any

from .models import Finding, Graph, VisibilityGap
from .schemas import SENSITIVE_DATA_CLASSES
from .validation.validate_inputs import all_tools


PRIVACY_CATEGORY_CLASSES = {
    "customer_pii": {"customer_pii", "customer_account_context", "support_history", "sales_correspondence", "vendor_pii", "zendesk_ticket_context"},
    "employee_data": {"employee_pii", "employee_data", "hr_data", "security_logs"},
    "credentials": {"secrets", "credentials", "api_keys", "tokens", "production_config"},
    "payment_data": {"payment_data", "billing_data", "financial_data", "cardholder_data", "sales_discount_terms"},
    "source_code": {"source_code", "repository_content"},
    "regulated_records": {"regulated_records", "health_data", "medical_data", "phi", "pci", "legal_records", "tax_records"},
}

DATA_RULES = {
    "untrusted_input_to_sensitive_data_to_external_sink",
    "persistent_memory_sensitive_data_gap",
    "financial_action_without_approval",
    "production_change_without_approval",
}


def build_privacy_analysis(
    evidence: dict[str, Any],
    graph: Graph,
    findings: list[Finding],
    visibility_gaps: list[VisibilityGap],
) -> dict[str, Any]:
    data_sources = (evidence.get("data_catalog") or {}).get("data_sources") or []
    memory_stores = (evidence.get("agents") or {}).get("memory_stores") or []
    classification_gaps = _classification_gaps(evidence, data_sources, memory_stores, visibility_gaps)
    data_exposures = _data_exposures(graph, findings)
    memory_retention = [_memory_retention_item(memory) for memory in memory_stores]
    category_counts = {category: 0 for category in PRIVACY_CATEGORY_CLASSES}
    for exposure in data_exposures:
        for category in exposure["privacy_categories"]:
            category_counts[category] += 1
    return {
        "summary": {
            "data_sources": len(data_sources),
            "classified_data_sources": len([item for item in data_sources if item.get("data_classes") and item.get("sensitivity") not in {"", "unknown"}]),
            "classification_gaps": len(classification_gaps),
            "memory_stores": len(memory_stores),
            "memory_stores_with_retention": len([item for item in memory_retention if item["status"] == "complete"]),
            "memory_retention_gaps": len([item for item in memory_retention if item["status"] in {"missing", "partial"}]),
            "findings_touching_regulated_data": len([item for item in data_exposures if item["privacy_categories"]]),
            "privacy_categories": category_counts,
        },
        "data_exposures": data_exposures,
        "classification_gaps": classification_gaps,
        "memory_retention": memory_retention,
        "privacy_filters": [
            {"id": "customer_pii", "label": "Customer PII", "data_classes": sorted(PRIVACY_CATEGORY_CLASSES["customer_pii"])},
            {"id": "employee_data", "label": "Employee data", "data_classes": sorted(PRIVACY_CATEGORY_CLASSES["employee_data"])},
            {"id": "credentials", "label": "Credentials", "data_classes": sorted(PRIVACY_CATEGORY_CLASSES["credentials"])},
            {"id": "payment_data", "label": "Payment data", "data_classes": sorted(PRIVACY_CATEGORY_CLASSES["payment_data"])},
            {"id": "source_code", "label": "Source code", "data_classes": sorted(PRIVACY_CATEGORY_CLASSES["source_code"])},
            {"id": "regulated_records", "label": "Regulated records", "data_classes": sorted(PRIVACY_CATEGORY_CLASSES["regulated_records"])},
        ],
    }


def privacy_categories_for_classes(data_classes: list[str]) -> list[str]:
    classes = {str(item).lower() for item in data_classes}
    categories = [
        category
        for category, category_classes in PRIVACY_CATEGORY_CLASSES.items()
        if classes.intersection(category_classes)
    ]
    return sorted(categories)


def privacy_filter_tokens_for_text(text: str) -> list[str]:
    lowered = text.lower()
    tokens = set()
    for category, category_classes in PRIVACY_CATEGORY_CLASSES.items():
        if category in lowered or any(data_class in lowered for data_class in category_classes):
            tokens.add(category)
            tokens.update(category_classes)
    return sorted(tokens)


def _classification_gaps(
    evidence: dict[str, Any],
    data_sources: list[dict[str, Any]],
    memory_stores: list[dict[str, Any]],
    visibility_gaps: list[VisibilityGap],
) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for data_source in data_sources:
        missing_parts = []
        if not data_source.get("data_classes"):
            missing_parts.append("data_classes")
        if data_source.get("sensitivity") in {"", "unknown"}:
            missing_parts.append("sensitivity")
        if missing_parts:
            gaps.append(
                {
                    "id": f"privacy-classification-gap-{data_source.get('id', 'unknown')}",
                    "type": "data_source_classification_gap",
                    "target": data_source.get("id", "unknown"),
                    "reason": f"Data source is missing {', '.join(missing_parts)}.",
                    "requested_evidence": "Provide data catalog, DLP, sensitivity-label, or table/object classification export.",
                    "source_file": data_source.get("source_file", ""),
                }
            )
    for memory in memory_stores:
        if not memory.get("data_classes"):
            gaps.append(
                {
                    "id": f"privacy-memory-classification-gap-{memory.get('id', 'unknown')}",
                    "type": "memory_classification_gap",
                    "target": memory.get("id", "unknown"),
                    "reason": "Memory store has no declared data classes.",
                    "requested_evidence": "Classify memory contents and provide retention/deletion evidence.",
                    "source_file": memory.get("source_file", ""),
                }
            )
    classified_targets = {
        item.get("target_system")
        for item in data_sources
        if item.get("target_system") not in {"", "unknown"} and (item.get("data_classes") or item.get("sensitivity") not in {"", "unknown"})
    }
    for tool in all_tools(evidence):
        risk_tags = set(tool.get("risk_tags", []))
        target_system = tool.get("target_system", "unknown")
        if risk_tags.intersection({"sensitive_read", "secret_access"}) and target_system not in classified_targets:
            gaps.append(
                {
                    "id": f"privacy-tool-classification-gap-{tool.get('id', 'unknown')}",
                    "type": "tool_target_classification_gap",
                    "target": tool.get("id", "unknown"),
                    "reason": f"Sensitive tool target {target_system} has no matching classified data source.",
                    "requested_evidence": "Export data catalog or object classification evidence for the tool target system.",
                    "source_file": tool.get("source_file", ""),
                }
            )
    for gap in visibility_gaps:
        if "data" in gap.type or "classification" in gap.reason.lower() or "memory" in gap.type:
            gaps.append(
                {
                    "id": gap.id,
                    "type": gap.type,
                    "target": gap.target,
                    "reason": gap.reason,
                    "requested_evidence": gap.requested_evidence,
                    "source_file": "",
                }
            )
    return _dedupe_by_id(gaps)


def _data_exposures(graph: Graph, findings: list[Finding]) -> list[dict[str, Any]]:
    exposures: list[dict[str, Any]] = []
    for finding in findings:
        data_classes = set()
        source_nodes = []
        for node_id in finding.nodes:
            node = graph.nodes.get(node_id)
            if not node:
                continue
            properties = node.properties or {}
            if node.type in {"data_source", "memory_store"}:
                source_nodes.append(node_id)
                data_classes.update(str(item) for item in properties.get("data_classes", []) if item)
        text = " ".join(
            [
                finding.title,
                finding.description,
                " ".join(finding.path),
                " ".join(finding.evidence),
                json.dumps(finding.scoring.to_dict() if finding.scoring else {}, default=str),
            ]
        ).lower()
        for data_class in _known_data_classes():
            if data_class in text:
                data_classes.add(data_class)
        categories = privacy_categories_for_classes(sorted(data_classes))
        if not data_classes and finding.rule_id not in DATA_RULES:
            continue
        exposures.append(
            {
                "finding_id": finding.id,
                "rule_id": finding.rule_id,
                "title": finding.title,
                "tier": finding.tier,
                "agent": (finding.operational_context or {}).get("agent", ""),
                "data_classes": sorted(data_classes),
                "privacy_categories": categories,
                "source_nodes": source_nodes,
                "evidence": finding.evidence[:5],
                "missing_classification": any("classification" in unknown.lower() for unknown in finding.unknowns),
            }
        )
    return exposures


def _memory_retention_item(memory: dict[str, Any]) -> dict[str, Any]:
    data_classes = memory.get("data_classes", [])
    sensitive = sorted(set(data_classes).intersection(SENSITIVE_DATA_CLASSES))
    retention_policy = memory.get("retention_policy", "")
    retention_period = memory.get("retention_period", "")
    deletion_policy = memory.get("deletion_policy", "")
    if not sensitive:
        status = "not_sensitive"
    elif retention_policy in {"", "unknown"}:
        status = "missing"
    elif not retention_period or not deletion_policy:
        status = "partial"
    else:
        status = "complete"
    missing = []
    if sensitive and retention_policy in {"", "unknown"}:
        missing.append("retention_policy")
    if sensitive and not retention_period:
        missing.append("retention_period")
    if sensitive and not deletion_policy:
        missing.append("deletion_policy")
    return {
        "id": memory.get("id", ""),
        "owner": memory.get("owner", ""),
        "persistence": memory.get("persistence", "unknown"),
        "retention_policy": retention_policy or "unknown",
        "retention_period": retention_period,
        "deletion_policy": deletion_policy,
        "data_classes": data_classes,
        "privacy_categories": privacy_categories_for_classes(data_classes),
        "source_file": memory.get("source_file", ""),
        "source_evidence": memory.get("source_evidence", []),
        "status": status,
        "missing": missing,
    }


def _known_data_classes() -> set[str]:
    values = set(SENSITIVE_DATA_CLASSES)
    for category_classes in PRIVACY_CATEGORY_CLASSES.values():
        values.update(category_classes)
    return values


def _dedupe_by_id(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for item in items:
        deduped.setdefault(item.get("id", ""), item)
    return list(deduped.values())
