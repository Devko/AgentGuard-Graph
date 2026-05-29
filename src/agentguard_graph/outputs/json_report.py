"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..errors import EvidenceLoadError


def write_json_report(report: dict[str, Any], path: str | Path) -> None:
    output_path = Path(path)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError as exc:
        raise EvidenceLoadError(f"{output_path}: cannot write JSON report: {exc}") from exc
