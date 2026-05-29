from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agentguard_graph.graph.builder import build_graph
from agentguard_graph.graph.findings import assemble_report
from agentguard_graph.graph.paths import analyze_attack_paths
from agentguard_graph.validation.validate_inputs import load_evidence


def sample_paths(name: str) -> dict[str, str]:
    base = ROOT / "samples" / name
    return {
        "agents": str(base / "agentguard.json"),
        "mcp": str(base / "mcp-servers.json"),
        "identity": str(base / "identity.json"),
        "data_catalog": str(base / "data-catalog.json"),
        "approval_policy": str(base / "approval-policy.json"),
        "events": str(base / "events.jsonl"),
    }


def load_sample(name: str = "support-agent") -> dict:
    return load_evidence(**sample_paths(name))


def build_report(evidence: dict) -> dict:
    graph, gaps = build_graph(evidence)
    paths, findings, all_gaps = analyze_attack_paths(evidence, gaps)
    return assemble_report(evidence, graph, findings, paths, all_gaps)


def load_report(name: str = "support-agent") -> dict:
    return build_report(load_sample(name))


def clone_sample(name: str = "support-agent") -> dict:
    return deepcopy(load_sample(name))


def write_json(path: Path, data: dict) -> str:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return str(path)
