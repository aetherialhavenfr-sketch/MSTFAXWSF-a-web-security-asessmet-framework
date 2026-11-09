"""FFUF: directory and file discovery."""
from __future__ import annotations

import json
import re

from .. import dependencies as dep
from .. import ui
from ..config import resolve_wordlist
from ..models import ModuleResult
from .base import Context, ExternalToolModule, SkipModule, classify_path

RESULT_RE = re.compile(
    r"^(?P<word>\S+)\s+\[Status:\s*(?P<status>\d+),\s*Size:\s*(?P<size>\d+),\s*"
    r"Words:\s*(?P<words>\d+),\s*Lines:\s*(?P<lines>\d+)"
)
BANNER_RE = re.compile(r"^[\s/\\'_,]{4,}$")  # lines drawn only with the logo's glyph characters
PROGRESS_RE = re.compile(r"::\s*Progress:")
MAX_STORED = 2000


class FfufModule(ExternalToolModule):
    key = "ffuf"
    tool = "ffuf"
    title = "FFUF"
    description = "Directory discovery"

    def build_command(self, ctx: Context, path: str, res: ModuleResult) -> list:
        cfg = ctx.profile["ffuf"]
        try:
            wordlist = resolve_wordlist(cfg["wordlist"], ctx.opts.get("wordlist"))
        except FileNotFoundError as exc:
            raise SkipModule(str(exc))
        out_file = ctx.raw("ffuf.json")
        if out_file.exists():
            out_file.unlink()
        res.raw_file = "raw/ffuf.json"
        res.data["wordlist"] = str(wordlist)
        ctx.say("ffuf", f"wordlist: {wordlist}", ui.GREY)

        cmd = [path, "-u", f"{ctx.base_url}/FUZZ", "-w", str(wordlist),
               "-mc", "200,204,301,302,307,401,403", "-t", str(cfg["threads"]),
               "-rate", str(cfg["rate"]), "-timeout", "10", "-maxtime", str(cfg["maxtime"]),
               "-H", f"User-Agent: {ctx.user_agent}", "-o", str(out_file), "-of", "json"]
        if cfg.get("extensions"):
            cmd += ["-e", cfg["extensions"]]
        cmd += dep.optional_flags("ffuf", ("-ac",), ("-noninteractive",))
        return cmd

    def format_line(self, ctx: Context, line: str) -> list:
        if PROGRESS_RE.search(line):
            ui.status("  " + line.strip(": ").strip())
            return []
        if BANNER_RE.search(line) or re.match(r"^\s*v\d", line):
            return []
        m = RESULT_RE.match(line)
        if m:
            status = int(m["status"])
            color = ui.WHITE if status < 300 else ui.ORANGE if status in (401, 403) else ui.GREY
            hit = classify_path("/" + m["word"], status)
            if hit and hit[0] in ("critical", "high", "medium"):
                color = ui.RED
            return [(line, color)]
        return [(line, ui.DIM)]

    def parse(self, ctx: Context, res: ModuleResult, lines: list) -> None:
        rows = []
        try:
            data = json.loads(ctx.raw("ffuf.json").read_text(errors="replace"))
            for r in data.get("results", []):
                rows.append({"url": r.get("url", ""), "status": r.get("status"),
                             "length": r.get("length"), "words": r.get("words"),
                             "lines": r.get("lines"), "redirect": r.get("redirectlocation", "")})
        except (OSError, json.JSONDecodeError, AttributeError):
            for line in lines:  # fallback: parse live text output
                m = RESULT_RE.match(line)
                if m:
                    rows.append({"url": f"{ctx.base_url}/{m['word']}", "status": int(m["status"]),
                                 "length": int(m["size"]), "words": int(m["words"]),
                                 "lines": int(m["lines"]), "redirect": ""})
        rows.sort(key=lambda r: (r["status"] or 0, r["url"]))
        res.data.update(directories=rows[:MAX_STORED], count=len(rows))
        if not rows:
            return
        by_status: dict = {}
        for r in rows:
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        summary = ", ".join(f"{n}x {s}" for s, n in sorted(by_status.items(), key=lambda kv: kv[0] or 0))
        res.add("info", f"{len(rows)} paths discovered", summary, ctx.base_url)
        for r in rows:
            hit = classify_path(r["url"], r["status"])
            if hit:
                res.add(hit[0], f"{hit[1]} (HTTP {r['status']})", url=r["url"])
