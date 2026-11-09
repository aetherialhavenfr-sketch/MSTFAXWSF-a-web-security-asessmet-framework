"""Shared data models used by every module, the engine and the report writers."""
from __future__ import annotations

import datetime as dt
from dataclasses import asdict, dataclass, field
from typing import Optional

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


@dataclass
class Finding:
    tool: str
    severity: str
    title: str
    detail: str = ""
    url: str = ""
    reference: str = ""


@dataclass
class ModuleResult:
    key: str
    name: str
    status: str = "pending"  # ok | failed | timeout | interrupted | missing | skipped
    started: str = ""
    duration: float = 0.0
    command: str = ""
    error: str = ""
    raw_file: str = ""
    findings: list = field(default_factory=list)
    data: dict = field(default_factory=dict)

    def add(self, severity: str, title: str, detail: str = "", url: str = "",
            reference: str = "") -> None:
        if severity not in SEV_RANK:
            severity = "info"
        self.findings.append(Finding(self.key, severity, title, detail, url, reference))


@dataclass
class Target:
    raw: str
    host: str
    scheme: str = ""
    port: Optional[int] = None
    path: str = ""
    base_url: str = ""

    @property
    def netloc(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}" if self.port else host

    @property
    def display(self) -> str:
        return self.host + (f":{self.port}" if self.port else "")

    def url_for(self, scheme: str) -> str:
        return f"{scheme}://{self.netloc}{self.path}"


@dataclass
class ScanSession:
    id: str
    target: dict
    profile: str
    started: str
    finished: str = ""
    duration: float = 0.0
    aborted: bool = False
    modules: list = field(default_factory=list)
    authorization: dict = field(default_factory=dict)
    system: dict = field(default_factory=dict)
    version: str = ""
    outdir: str = ""

    def findings(self) -> list:
        out = []
        for m in self.modules:
            out.extend(m.findings)
        return sorted(out, key=lambda f: SEV_RANK.get(f.severity, 99))

    def counts(self) -> dict:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.findings():
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        data = asdict(self)
        data["schema"] = "mstfaxwsf-report/1"
        data["counts"] = self.counts()
        return data
