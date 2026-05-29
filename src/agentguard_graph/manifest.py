"""Offline evidence manifest helpers."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__


MANIFEST_FILE_NAME = "evidence-manifest.json"
MANIFEST_SCHEMA_VERSION = "0.1"
TOOL_NAME = "agentguard-graph"


SOURCE_KIND_BY_NAME = {
    "agentguard.json": "agent_inventory",
    "mcp-servers.json": "tool_descriptors",
    "identity.json": "identity",
    "data-catalog.json": "data_catalog",
    "approval-policy.json": "approval_policy",
    "events.jsonl": "runtime_events",
    "collector-summary.json": "collector_summary",
}


def write_evidence_manifest(evidence_dir: Path, generated_files: list[str]) -> dict[str, Any]:
    manifest = build_evidence_manifest(evidence_dir, generated_files)
    path = evidence_dir / MANIFEST_FILE_NAME
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def build_evidence_manifest(evidence_dir: Path, generated_files: list[str]) -> dict[str, Any]:
    root = evidence_dir.resolve()
    entries = []
    for relative_path in _unique_relative_paths(generated_files):
        path = evidence_dir / relative_path
        if not path.is_file():
            continue
        entries.append(file_manifest_entry(path, evidence_dir))
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "root": str(root),
        "files": entries,
    }


def file_manifest_entry(path: Path, evidence_dir: Path) -> dict[str, Any]:
    content = path.read_bytes()
    relative_path = _relative_manifest_path(path, evidence_dir)
    entry: dict[str, Any] = {
        "path": relative_path,
        "sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
    }
    source_kind = infer_source_kind(relative_path)
    if source_kind:
        entry["source_kind"] = source_kind
    schema_version = infer_schema_version(path)
    if schema_version:
        entry["schema_version"] = schema_version
    return entry


def empty_evidence_manifest_status(status: str) -> dict[str, Any]:
    return _empty_manifest_status(status)


def validate_evidence_manifest(evidence_dir: str | Path | None, conventional_files: list[Path]) -> dict[str, Any]:
    if not evidence_dir:
        return _empty_manifest_status("not_provided")
    base = Path(evidence_dir)
    manifest_path = base / MANIFEST_FILE_NAME
    if not manifest_path.is_file():
        return _empty_manifest_status("missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {
            **_empty_manifest_status("present"),
            "path": str(manifest_path),
            "errors": [f"cannot read evidence manifest: {exc}"],
        }

    files = manifest.get("files", [])
    if not isinstance(files, list):
        return {
            **_empty_manifest_status("present"),
            "path": str(manifest_path),
            "errors": ["evidence manifest files must be a list"],
        }

    changed: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    checked_count = 0
    manifest_paths: set[str] = set()
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        relative_path = _normalize_manifest_path(item["path"])
        manifest_paths.add(relative_path)
        path = _manifest_child_path(base, relative_path)
        if path is None:
            missing.append({"path": relative_path, "reason": "path escapes evidence directory"})
            continue
        if not path.is_file():
            missing.append({"path": relative_path})
            continue
        checked_count += 1
        actual = file_manifest_entry(path, base)
        differences = []
        for field in ["sha256", "size_bytes"]:
            if item.get(field) != actual.get(field):
                differences.append(field)
        if differences:
            changed.append({"path": relative_path, "fields": differences})

    unmanifested = [
        {"path": relative_path}
        for relative_path in sorted(
            {
                _relative_manifest_path(path, base)
                for path in conventional_files
                if path.is_file() and path.name != MANIFEST_FILE_NAME
            }
            - manifest_paths
        )
    ]
    return {
        "status": "present",
        "path": str(manifest_path),
        "summary": {
            "checked_count": checked_count,
            "changed_count": len(changed),
            "missing_count": len(missing),
            "unmanifested_count": len(unmanifested),
        },
        "changed": changed,
        "missing": missing,
        "unmanifested": unmanifested,
        "errors": [],
    }


def infer_source_kind(relative_path: str) -> str:
    normalized = _normalize_manifest_path(relative_path)
    if normalized.startswith("openapi/") and normalized.endswith(".json"):
        return "openapi"
    return SOURCE_KIND_BY_NAME.get(Path(normalized).name, "")


def infer_schema_version(path: Path) -> str:
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("schema_version") is not None:
                return str(data["schema_version"])
        if suffix == ".jsonl":
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    data = json.loads(line)
                    if isinstance(data, dict) and data.get("schema_version") is not None:
                        return str(data["schema_version"])
                    return ""
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ""
    return ""


def _empty_manifest_status(status: str) -> dict[str, Any]:
    return {
        "status": status,
        "path": "",
        "summary": {
            "checked_count": 0,
            "changed_count": 0,
            "missing_count": 0,
            "unmanifested_count": 0,
        },
        "changed": [],
        "missing": [],
        "unmanifested": [],
        "errors": [],
    }


def _relative_manifest_path(path: Path, evidence_dir: Path) -> str:
    try:
        relative = path.resolve().relative_to(evidence_dir.resolve())
    except ValueError:
        relative = path
    return _normalize_manifest_path(str(relative))


def _normalize_manifest_path(path: str) -> str:
    return Path(path).as_posix()


def _manifest_child_path(evidence_dir: Path, relative_path: str) -> Path | None:
    path = evidence_dir / Path(relative_path)
    try:
        path.resolve().relative_to(evidence_dir.resolve())
    except ValueError:
        return None
    return path


def _unique_relative_paths(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    unique = []
    for path in paths:
        normalized = _normalize_manifest_path(path)
        if normalized in seen:
            continue
        seen.add(normalized)
        unique.append(normalized)
    return unique
