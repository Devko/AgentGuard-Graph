"""Adapter for runtime event JSONL evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..schemas import load_jsonl_file, source_name, string_list


def parse_events(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {"events": [], "source_file": None}
    raw_events = load_jsonl_file(path)
    source = source_name(path)
    events = []
    for index, item in enumerate(raw_events, start=1):
        event_id = str(item.get("id") or f"event-{index:03d}")
        events.append(
            {
                "id": event_id,
                "event_type": str(item.get("event_type", "unknown")),
                "timestamp": str(item.get("timestamp", "")),
                "agent": str(item.get("agent", "")),
                "session_id": str(item.get("session_id", "")),
                "delegated_by": str(item.get("delegated_by", "")),
                "input_source": str(item.get("input_source", "")),
                "input_trust": str(item.get("input_trust", "")),
                "tool": str(item.get("tool", "")),
                "action_class": str(item.get("action_class", "")),
                "data_classes": string_list(item.get("data_classes")),
                "identity": str(item.get("identity", "")),
                "target": str(item.get("target", "")),
                "decision": str(item.get("decision", "unknown")),
                "policy": str(item.get("policy", "")),
                "confidence": str(item.get("confidence", "medium")),
                "source_file": source,
                "line": index,
                "raw": item,
            }
        )
    return {"events": events, "source_file": source}
