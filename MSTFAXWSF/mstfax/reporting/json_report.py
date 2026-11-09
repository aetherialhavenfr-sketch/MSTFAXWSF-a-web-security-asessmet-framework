"""JSON report: the complete scan session, suitable for pipelines and re-rendering."""
from __future__ import annotations

import json
from pathlib import Path


def write(data: dict, path: Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    return path
