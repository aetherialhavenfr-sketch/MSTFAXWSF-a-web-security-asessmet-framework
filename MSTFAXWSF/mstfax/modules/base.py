"""Base classes for pipeline modules plus helpers shared by several of them."""
from __future__ import annotations

import json
import re
import shlex
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from .. import dependencies, ui
from ..config import PROFILES, USER_AGENT
from ..models import ModuleResult, Target, now_iso
from ..runner import run_streaming


class SkipModule(Exception):
    """Raised by build_command() when a module cannot run (reason in the message)."""


class Context:
    """State shared by all modules during one scan."""

    def __init__(self, target: Target, profile_name: str, outdir: Path, opts: Optional[dict] = None):
        self.target = target
        self.profile_name = profile_name
        self.profile = PROFILES[profile_name]
        self.outdir = Path(outdir)
        self.raw_dir = self.outdir / "raw"
        self.opts = opts or {}
        self.results: dict = {}
        self.reachable = True

    @property
    def base_url(self) -> str:
        return (self.target.base_url or self.target.url_for(self.target.scheme or "http")).rstrip("/")

    @property
    def quiet(self) -> bool:
        return bool(self.opts.get("quiet"))

    @property
    def user_agent(self) -> str:
        return self.opts.get("user_agent") or USER_AGENT

    def raw(self, name: str) -> Path:
        return self.raw_dir / name

    def say(self, tool: str, text: str, color=None) -> None:
        if not self.quiet:
            ui.live(tool, text, color)


# --- shared heuristics -------------------------------------------------------
INTERESTING = [
    (re.compile(r"/\.git(/|$)", re.I), "high", "Exposed .git repository path"),
    (re.compile(r"/\.env($|\.)", re.I), "high", "Exposed environment file"),
    (re.compile(r"/(\.htpasswd|\.svn|\.DS_Store)$", re.I), "medium", "Sensitive metadata file"),
    (re.compile(r"\.(sql|bak|old|orig|swp|zip|tar|gz|7z|dump)$", re.I), "medium",
     "Possible backup or archive file"),
    (re.compile(r"phpinfo", re.I), "medium", "phpinfo() page exposed"),
    (re.compile(r"/(server-status|server-info|actuator|web\.config|\.htaccess)(/|$)", re.I),
     "medium", "Server status or configuration resource"),
    (re.compile(r"/(phpmyadmin|pma|adminer|wp-admin|administrator|cpanel|manager/html)(/|$|\.)", re.I),
     "low", "Administrative interface"),
    (re.compile(r"/(admin|dashboard|console)(/|$)", re.I), "low", "Administrative area"),
    (re.compile(r"/(swagger|openapi|graphql|api-docs)", re.I), "info", "API endpoint or documentation"),
    (re.compile(r"/(login|signin|auth)(/|$|\.)", re.I), "info", "Authentication endpoint"),
]

_DOWN = {"critical": "high", "high": "medium", "medium": "low", "low": "info", "info": "info"}


def classify_path(url: str, status: Optional[int] = None):
    """Return (severity, label) when a URL looks interesting, else None."""
    path = urlsplit(url).path or "/"
    for pattern, severity, label in INTERESTING:
        if pattern.search(path):
            if status in (401, 403):
                severity = _DOWN[_DOWN[severity]]
            elif status and 300 <= status < 400:
                severity = _DOWN[severity]
            return severity, label
    return None


def same_host(url: str, host: str) -> bool:
    try:
        return (urlsplit(url).hostname or "").lower() == host.lower()
    except ValueError:
        return False


def load_json_flexible(path: Path) -> list:
    """Read a JSON array, a single object or JSON-lines (tolerates truncated files)."""
    try:
        text = Path(path).read_text(errors="replace").strip()
    except OSError:
        return []
    if not text:
        return []
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        pass
    records = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            line = line[1:]
        line = line.rstrip(",").rstrip("]").rstrip(",")
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


class BaseModule:
    key = ""
    title = ""
    description = ""

    def run(self, ctx: Context) -> ModuleResult:  # pragma: no cover - interface
        raise NotImplementedError


class ExternalToolModule(BaseModule):
    """Template for modules that wrap an external command-line tool."""

    tool = ""

    # -- hooks -------------------------------------------------------------
    def build_command(self, ctx: Context, path: str, res: ModuleResult) -> list:
        raise NotImplementedError

    def parse(self, ctx: Context, res: ModuleResult, lines: list) -> None:
        raise NotImplementedError

    def format_line(self, ctx: Context, line: str) -> list:
        """Return a list of (text, colour) tuples to print live; [] to hide the line."""
        return [(line, None)]

    # -- pipeline ----------------------------------------------------------
    def timeout(self, ctx: Context) -> int:
        return int(ctx.profile[self.key]["timeout"])

    def run(self, ctx: Context) -> ModuleResult:
        res = ModuleResult(key=self.key, name=self.title, started=now_iso())
        t0 = time.monotonic()
        path = dependencies.tool_path(self.tool)
        if not path:
            res.status = "missing"
            res.error = f"{self.tool} is not installed. Run: mstfaxwsf tools --install"
            return res
        try:
            cmd = self.build_command(ctx, path, res)
        except SkipModule as exc:
            res.status = "skipped"
            res.error = str(exc)
            return res

        res.command = shlex.join(cmd)
        ui.dim("$ " + res.command)

        def on_line(line: str) -> None:
            if ctx.quiet:
                return
            for text, color in self.format_line(ctx, line):
                ui.live(self.tool, text, color)

        def on_idle(elapsed: float) -> None:
            frame = ui.SPINNER[int(elapsed) % len(ui.SPINNER)]
            ui.status(f"  {frame} {self.title} running... {int(elapsed // 60):02d}:{int(elapsed % 60):02d}"
                      "   (Ctrl+C skips this tool)")

        rr = run_streaming(cmd, on_line=on_line, timeout=self.timeout(ctx),
                           cwd=str(ctx.raw_dir), on_idle=on_idle)
        ui.clear_status()
        res.duration = round(time.monotonic() - t0, 1)
        try:
            ctx.raw(f"{self.key}.log").write_text("\n".join(rr.lines))
        except OSError:
            pass
        if rr.error:
            res.status, res.error = "failed", rr.error
            return res
        try:
            self.parse(ctx, res, rr.lines)
        except Exception as exc:  # parser bugs must never kill the scan
            res.error = f"Parse error: {type(exc).__name__}: {exc}"

        produced = bool(res.findings) or bool(res.data.get("count"))
        if rr.interrupted:
            res.status = "interrupted"
        elif rr.timed_out:
            res.status = "timeout"
            res.error = res.error or f"Stopped after {self.timeout(ctx)}s time limit (partial results kept)."
        elif rr.returncode not in (0, None) and not produced:
            res.status = "failed"
            tail = [l for l in rr.lines if l.strip()][-3:]
            res.error = res.error or ("; ".join(tail) or f"exit code {rr.returncode}")
        else:
            res.status = "ok"
        return res
