"""Core dataclasses for AgentGuard Graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .schemas import EDGE_TYPES


CONFIDENCE_ORDER = {"low": 1, "medium": 2, "high": 3}


def _default_accepted_risk() -> dict[str, Any]:
    return {"status": "open", "accepted": False, "expired": False, "expires_at": ""}


def confidence_min(values: list[str]) -> str:
    known = [value for value in values if value in CONFIDENCE_ORDER]
    if not known:
        return "low"
    return min(known, key=lambda value: CONFIDENCE_ORDER[value])


def confidence_max(values: list[str]) -> str:
    known = [value for value in values if value in CONFIDENCE_ORDER]
    if not known:
        return "low"
    return max(known, key=lambda value: CONFIDENCE_ORDER[value])


@dataclass
class Node:
    id: str
    type: str
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    source: str = "unknown"
    confidence: str = "medium"
    evidence_layer: str = "static"
    unknowns: list[str] = field(default_factory=list)
    visibility_gaps: list[str] = field(default_factory=list)
    visibility_gap_priorities: list[str] = field(default_factory=list)
    recommended_next_evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "properties": self.properties,
            "source": self.source,
            "confidence": self.confidence,
            "evidence_layer": self.evidence_layer,
            "unknowns": self.unknowns,
            "visibility_gaps": self.visibility_gaps,
            "visibility_gap_priorities": self.visibility_gap_priorities,
            "recommended_next_evidence": self.recommended_next_evidence,
        }


@dataclass
class Edge:
    id: str
    from_node: str
    to_node: str
    type: str
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    source: str = "unknown"
    confidence: str = "medium"
    evidence_layer: str = "static"
    unknowns: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    visibility_gaps: list[str] = field(default_factory=list)
    visibility_gap_priorities: list[str] = field(default_factory=list)
    recommended_next_evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "from_node": self.from_node,
            "to_node": self.to_node,
            "type": self.type,
            "label": self.label,
            "properties": self.properties,
            "source": self.source,
            "confidence": self.confidence,
            "evidence_layer": self.evidence_layer,
            "unknowns": self.unknowns,
            "blockers": self.blockers,
            "visibility_gaps": self.visibility_gaps,
            "visibility_gap_priorities": self.visibility_gap_priorities,
            "recommended_next_evidence": self.recommended_next_evidence,
        }


@dataclass
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: dict[str, Edge] = field(default_factory=dict)

    def add_node(self, node: Node) -> None:
        if node.id in self.nodes:
            existing = self.nodes[node.id]
            existing.properties.update(node.properties)
            if existing.source == "unknown":
                existing.source = node.source
            existing.confidence = confidence_max([existing.confidence, node.confidence])
            existing.unknowns = sorted(set(existing.unknowns + node.unknowns))
            existing.visibility_gaps = sorted(set(existing.visibility_gaps + node.visibility_gaps))
            existing.recommended_next_evidence = sorted(
                set(existing.recommended_next_evidence + node.recommended_next_evidence)
            )
            return
        self.nodes[node.id] = node

    def add_edge(self, edge: Edge) -> None:
        if edge.type not in EDGE_TYPES:
            raise ValueError(f"undeclared graph edge type: {edge.type}")
        if edge.id not in self.edges:
            self.edges[edge.id] = edge

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in sorted(self.nodes.values(), key=lambda item: item.id)],
            "edges": [edge.to_dict() for edge in sorted(self.edges.values(), key=lambda item: item.id)],
        }


@dataclass
class VisibilityGap:
    id: str
    type: str
    target: str
    reason: str
    requested_evidence: str
    severity: str = "medium"
    priority: str = "medium_gap"
    affected_findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "target": self.target,
            "reason": self.reason,
            "requested_evidence": self.requested_evidence,
            "severity": self.severity,
            "priority": self.priority,
            "affected_findings": self.affected_findings,
        }


@dataclass
class ScoringDimension:
    name: str
    points: int
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "points": self.points, "evidence": self.evidence}


@dataclass
class ScoreResult:
    score: int
    tier: str
    dimensions: list[ScoringDimension] = field(default_factory=list)
    caps: list[str] = field(default_factory=list)
    controls: list[ScoringDimension] = field(default_factory=list)
    raw_points: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "raw_points": self.raw_points or self.score,
            "tier": self.tier,
            "dimensions": [item.to_dict() for item in self.dimensions],
            "caps": self.caps,
            "controls": [item.to_dict() for item in self.controls],
        }


@dataclass
class AttackPath:
    id: str
    rule_id: str
    title: str
    nodes: list[str]
    edges: list[str]
    evidence_summary: list[str]
    unknowns: list[str]
    blockers: list[str]
    score: int
    tier: str
    recommendations: list[str]
    confidence: str = "medium"
    evidence_layer: str = "analysis"
    observation_status: str = "possible_static"
    path_state: str = "possible"
    evidence_quality: str = "incomplete"
    runtime_observation: dict[str, Any] = field(default_factory=dict)
    remediation: dict[str, Any] = field(default_factory=dict)
    operational_context: dict[str, Any] = field(default_factory=dict)
    risk_status: str = "open"
    accepted_risk: dict[str, Any] = field(default_factory=_default_accepted_risk)
    visibility_gaps: list[str] = field(default_factory=list)
    visibility_gap_priorities: list[str] = field(default_factory=list)
    recommended_next_evidence: list[str] = field(default_factory=list)
    scoring: ScoreResult | None = None
    related_events: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "nodes": self.nodes,
            "edges": self.edges,
            "evidence_summary": self.evidence_summary,
            "unknowns": self.unknowns,
            "blockers": self.blockers,
            "score": self.score,
            "tier": self.tier,
            "confidence": self.confidence,
            "evidence_layer": self.evidence_layer,
            "observation_status": self.observation_status,
            "path_state": self.path_state,
            "evidence_quality": self.evidence_quality,
            "runtime_observation": self.runtime_observation,
            "remediation": self.remediation,
            "operational_context": self.operational_context,
            "risk_status": self.risk_status,
            "accepted_risk": self.accepted_risk or _default_accepted_risk(),
            "recommendations": self.recommendations,
            "visibility_gaps": self.visibility_gaps,
            "visibility_gap_priorities": self.visibility_gap_priorities,
            "recommended_next_evidence": self.recommended_next_evidence,
            "scoring": self.scoring.to_dict() if self.scoring else None,
            "raw_points": self.scoring.raw_points if self.scoring else self.score,
            "related_events": self.related_events,
        }


@dataclass
class Finding:
    id: str
    title: str
    description: str
    tier: str
    score: int
    confidence: str
    path: list[str]
    nodes: list[str]
    edges: list[str]
    evidence: list[str]
    unknowns: list[str]
    blockers: list[str]
    controls: list[str]
    recommendations: list[str]
    source_files: list[str]
    related_events: list[str]
    evidence_layer: str = "analysis"
    observation_status: str = "possible_static"
    path_state: str = "possible"
    evidence_quality: str = "incomplete"
    runtime_observation: dict[str, Any] = field(default_factory=dict)
    remediation: dict[str, Any] = field(default_factory=dict)
    operational_context: dict[str, Any] = field(default_factory=dict)
    visibility_gaps: list[str] = field(default_factory=list)
    visibility_gap_priorities: list[str] = field(default_factory=list)
    recommended_next_evidence: list[str] = field(default_factory=list)
    scoring: ScoreResult | None = None
    finding_type: str = "attack_path"
    rule_id: str = ""
    risk_status: str = "open"
    accepted_risk: dict[str, Any] = field(default_factory=_default_accepted_risk)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "type": self.finding_type,
            "rule_id": self.rule_id,
            "tier": self.tier,
            "score": self.score,
            "confidence": self.confidence,
            "evidence_layer": self.evidence_layer,
            "observation_status": self.observation_status,
            "path_state": self.path_state,
            "evidence_quality": self.evidence_quality,
            "runtime_observation": self.runtime_observation,
            "remediation": self.remediation,
            "operational_context": self.operational_context,
            "risk_status": self.risk_status,
            "accepted_risk": self.accepted_risk or _default_accepted_risk(),
            "path": self.path,
            "nodes": self.nodes,
            "edges": self.edges,
            "evidence": self.evidence,
            "unknowns": self.unknowns,
            "blockers": self.blockers,
            "controls": self.controls,
            "recommendations": self.recommendations,
            "visibility_gaps": self.visibility_gaps,
            "visibility_gap_priorities": self.visibility_gap_priorities,
            "recommended_next_evidence": self.recommended_next_evidence,
            "source_files": self.source_files,
            "related_events": self.related_events,
            "scoring": self.scoring.to_dict() if self.scoring else None,
            "raw_points": self.scoring.raw_points if self.scoring else self.score,
        }
