"""Explainable additive scoring for attack paths."""

from __future__ import annotations

from ..models import ScoreResult, ScoringDimension

POINTS = {
    "untrusted_input": 20,
    "autonomous_agent": 15,
    "approval_required_agent": 5,
    "sensitive_data_medium": 10,
    "sensitive_data_high": 20,
    "sensitive_data_critical": 25,
    "external_sink": 20,
    "financial_action": 20,
    "production_write": 25,
    "command_execution": 25,
    "secret_access": 25,
    "persistent_memory_with_sensitive_data": 10,
    "runtime_observed_allowed": 15,
    "runtime_observed_blocked": 8,
    "missing_approval": 15,
    "unknown_identity_permissions": 8,
    "unknown_data_classification": 6,
    "mcp_dangerous_tool": 15,
}

CONTROL_POINTS = {
    "approval_required": -20,
    "explicit_deny_policy": -25,
    "sandbox_control": -15,
    "egress_allowlist": -10,
    "scoped_identity": -10,
    "read_only_identity": -8,
    "command_allowlist": -10,
    "secret_denylist": -10,
    "amount_threshold": -8,
    "audit_logging": -5,
    "change_ticket_required": -10,
    "dlp_redaction": -8,
    "blocked_runtime_event": -10,
}


def tier_for_score(score: int) -> str:
    if score >= 85:
        return "urgent"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "informational"


def _cap_score(score: int, cap_tier: str) -> int:
    caps = {"informational": 19, "low": 39, "medium": 64, "high": 84}
    return min(score, caps[cap_tier])


def score_path(context: dict[str, object]) -> ScoreResult:
    dimensions: list[ScoringDimension] = []
    controls: list[ScoringDimension] = []
    caps: list[str] = []

    for name, points in POINTS.items():
        evidence = context.get(name)
        if evidence:
            dimensions.append(ScoringDimension(name=name, points=points, evidence=str(evidence)))

    for name, points in CONTROL_POINTS.items():
        evidence = context.get(name)
        if evidence:
            controls.append(ScoringDimension(name=name, points=points, evidence=str(evidence)))

    score = sum(item.points for item in dimensions) + sum(item.points for item in controls)
    score = max(score, 0)
    raw_points = score

    confidences = [str(item) for item in context.get("confidences", []) if item]
    if confidences and set(confidences) == {"low"}:
        score = _cap_score(score, "medium")
        caps.append("all evidence is low confidence; capped at medium")

    if context.get("unknown_identity_permissions") and score < 75:
        score = _cap_score(score, "medium")
        caps.append("target IAM is unknown without enough strong corroborating evidence; capped at medium")

    if context.get("approval_blocks_path") and not context.get("critical_blocked_attempt"):
        score = _cap_score(score, "high")
        caps.append("approval or deny policy blocks the path; capped below urgent")

    if not context.get("has_sensitive_or_critical_action"):
        score = _cap_score(score, "medium")
        caps.append("no sensitive data or critical action present; capped below high")

    if context.get("visibility_gap_only"):
        score = _cap_score(score, "high")
        caps.append("visibility gap findings do not become urgent by themselves")

    evidence_quality = str(context.get("evidence_quality") or "")
    if evidence_quality == "weak":
        score = _cap_score(score, "low")
        caps.append("weak evidence is capped below medium")
    elif evidence_quality == "incomplete":
        score = _cap_score(score, "medium")
        caps.append("incomplete evidence is capped below high")

    if score > 100:
        score = 100
        caps.append("public score capped at 100")

    return ScoreResult(
        score=score,
        raw_points=raw_points,
        tier=tier_for_score(score),
        dimensions=dimensions,
        controls=controls,
        caps=caps,
    )
