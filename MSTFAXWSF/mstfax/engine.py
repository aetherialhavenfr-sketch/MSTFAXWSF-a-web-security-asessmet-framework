"""Scan engine: runs the module pipeline, handles Ctrl+C, writes reports and history."""
from __future__ import annotations

import datetime as dt
import getpass
import platform
import re
import socket
import time
from pathlib import Path
from typing import Optional

from . import __version__, dependencies, history, ui
from .config import MODULE_ORDER, PROFILES, SCANS_DIR, ensure_dirs
from .models import SEVERITIES, ModuleResult, ScanSession, Target, now_iso
from .modules import REGISTRY
from .modules.base import Context
from .reporting import html_report, json_report

ABORT_WINDOW = 6.0  # seconds: second Ctrl+C within this window aborts the whole scan


class ScanEngine:
    def __init__(self, target: Target, profile: str = "standard", modules: Optional[list] = None,
                 options: Optional[dict] = None, authorization: Optional[dict] = None):
        self.target = target
        self.profile = profile
        self.modules = [m for m in (modules or MODULE_ORDER) if m in REGISTRY]
        self.options = options or {}
        self.authorization = authorization or {}

    def _scan_id(self) -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", self.target.display)
        return f"{dt.datetime.now():%Y%m%d-%H%M%S}-{safe}"

    def _system(self) -> dict:
        tools = {}
        for key, st in dependencies.detect_all().items():
            tools[key] = {"installed": st.installed, "version": st.version, "path": st.path}
        return {"hostname": socket.gethostname(), "user": getpass.getuser(),
                "platform": platform.platform(), "python": platform.python_version(),
                "tools": tools}

    def run(self) -> ScanSession:
        ensure_dirs()
        scan_id = self._scan_id()
        outdir = SCANS_DIR / scan_id
        (outdir / "raw").mkdir(parents=True, exist_ok=True)

        session = ScanSession(
            id=scan_id, target={"input": self.target.raw, "host": self.target.host,
                                "port": self.target.port, "path": self.target.path},
            profile=self.profile, started=now_iso(), authorization=self.authorization,
            system=self._system(), version=__version__, outdir=str(outdir))
        ctx = Context(self.target, self.profile, outdir, self.options)
        t0 = time.monotonic()
        last_interrupt = -1e9
        total = len(self.modules)

        ui.info(f"Scan {ui.paint(scan_id, ui.WHITE, True)}  profile={self.profile}  "
                f"({PROFILES[self.profile]['description']})")
        ui.dim(f"Output directory: {outdir}")
        ui.dim("Ctrl+C skips the current tool; press it twice quickly to abort the scan.")
        ui.out()

        try:
            for index, key in enumerate(self.modules, 1):
                module = REGISTRY[key]()
                ui.rule(f"[{index}/{total}] {module.title} - {module.description}")
                if key != "recon" and not ctx.reachable:
                    res = ModuleResult(key=key, name=module.title, status="skipped",
                                       started=now_iso(), error="Target not reachable (see Recon).")
                else:
                    try:
                        res = module.run(ctx)
                    except KeyboardInterrupt:
                        res = ModuleResult(key=key, name=module.title, status="interrupted",
                                           started=now_iso())
                    except Exception as exc:  # a broken module must not stop the pipeline
                        res = ModuleResult(key=key, name=module.title, status="failed",
                                           started=now_iso(), error=f"{type(exc).__name__}: {exc}")
                ctx.results[key] = res
                session.modules.append(res)
                self._print_result(res)

                if res.status == "interrupted":
                    now = time.monotonic()
                    if now - last_interrupt < ABORT_WINDOW:
                        session.aborted = True
                        ui.warn("Scan aborted by user.")
                        break
                    last_interrupt = now
                    ui.warn(f"{module.title} skipped. Press Ctrl+C again within "
                            f"{int(ABORT_WINDOW)}s to abort the whole scan.")
                ui.out()
        except KeyboardInterrupt:
            session.aborted = True
            ui.clear_status()
            ui.warn("Scan aborted by user.")

        session.duration = round(time.monotonic() - t0, 1)
        session.finished = now_iso()
        self._write_outputs(session, outdir)
        return session

    # ------------------------------------------------------------------------
    def _print_result(self, res: ModuleResult) -> None:
        icon, color = {
            "ok": ("✔", ui.GREEN), "timeout": ("◔", ui.ORANGE), "interrupted": ("■", ui.ORANGE),
            "failed": ("✖", ui.RED), "missing": ("∅", ui.RED), "skipped": ("→", ui.GREY),
        }.get(res.status, ("?", ui.GREY))
        count = len(res.findings)
        line = (f" {ui.paint(icon, color, True)} {ui.paint(res.name, ui.WHITE, True)} "
                f"{ui.paint(res.status, color)}  {ui.paint(f'{res.duration:.0f}s', ui.GREY)}  "
                f"{ui.paint(f'{count} finding(s)', ui.GREY)}")
        ui.out(line)
        if res.error:
            ui.dim(res.error[:200])

    def _write_outputs(self, session: ScanSession, outdir: Path) -> None:
        data = session.to_dict()
        json_path = outdir / "report.json"
        html_path = outdir / "report.html"
        json_report.write(data, json_path)
        html_report.write(data, html_path)
        history.add(data, str(html_path), str(json_path))


def print_summary(session: ScanSession) -> None:
    counts = session.counts()
    ui.rule("SCAN COMPLETE")
    bar = "   ".join(
        f"{ui.paint(s.upper(), ui.SEV_STYLE[s][0], ui.SEV_STYLE[s][1])} {ui.paint(str(counts[s]), ui.WHITE, True)}"
        for s in SEVERITIES)
    ui.panel([f"Target   {ui.paint(session.target['host'], ui.WHITE, True)}",
              f"Profile  {session.profile}      Duration  {session.duration:.0f}s"
              + ("      " + ui.paint("ABORTED", ui.ORANGE, True) if session.aborted else ""),
              "", bar], title="Summary")
    top = [f for f in session.findings() if f.severity != "info"][:10]
    if top:
        ui.out()
        ui.out(f"  {ui.paint('Top findings', ui.WHITE, True)}")
        for f in top:
            where = f"  {ui.paint(f.url, ui.DIM)}" if f.url else ""
            ui.out(f"  {ui.sev_tag(f.severity)} {f.title[:90]}{where}")
    ui.out()
    ui.ok(f"HTML report: {session.outdir}/report.html")
    ui.ok(f"JSON report: {session.outdir}/report.json")
    ui.out()
