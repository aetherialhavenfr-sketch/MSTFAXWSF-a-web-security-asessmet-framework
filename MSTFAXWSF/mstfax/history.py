"""Scan history: a small JSON index of past scans, newest first."""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Optional

from .config import HISTORY_FILE, ensure_dirs


def _read() -> list:
    try:
        data = json.loads(HISTORY_FILE.read_text())
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _write(entries: list) -> None:
    ensure_dirs()
    tmp = HISTORY_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, indent=2))
    os.replace(tmp, HISTORY_FILE)


def add(session: dict, html_path: str, json_path: str) -> dict:
    entry = {
        "id": session["id"],
        "target": session["target"].get("host", ""),
        "profile": session["profile"],
        "started": session["started"],
        "duration": session["duration"],
        "aborted": session.get("aborted", False),
        "counts": session["counts"],
        "modules": {m["key"]: m["status"] for m in session["modules"]},
        "dir": session["outdir"],
        "report_html": html_path,
        "report_json": json_path,
    }
    entries = [e for e in _read() if e.get("id") != entry["id"]]
    entries.insert(0, entry)
    _write(entries)
    return entry


def list_entries() -> list:
    return _read()


def resolve(ref: str) -> Optional[dict]:
    """Find an entry by list number (1 = newest), exact id, or unique id prefix."""
    entries = _read()
    if not entries or not ref:
        return None
    if ref.isdigit() and 1 <= int(ref) <= len(entries):
        return entries[int(ref) - 1]
    exact = [e for e in entries if e["id"] == ref]
    if exact:
        return exact[0]
    prefix = [e for e in entries if e["id"].startswith(ref) or ref in e["id"]]
    return prefix[0] if len(prefix) == 1 else None


def delete(ref: str, remove_files: bool = True) -> bool:
    entry = resolve(ref)
    if not entry:
        return False
    _write([e for e in _read() if e["id"] != entry["id"]])
    if remove_files and entry.get("dir"):
        shutil.rmtree(entry["dir"], ignore_errors=True)
    return True


def clear(remove_files: bool = True) -> int:
    entries = _read()
    if remove_files:
        for e in entries:
            if e.get("dir"):
                shutil.rmtree(e["dir"], ignore_errors=True)
    _write([])
    return len(entries)


def load_session_json(entry: dict) -> Optional[dict]:
    try:
        return json.loads(Path(entry["report_json"]).read_text())
    except (OSError, json.JSONDecodeError, KeyError):
        return None
