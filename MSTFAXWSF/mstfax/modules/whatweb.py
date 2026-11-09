"""WhatWeb: website and technology fingerprinting."""
from __future__ import annotations

import re

from .. import ui
from ..models import ModuleResult
from .base import Context, ExternalToolModule, load_json_flexible

NOISE = {"Country", "IP", "HTML5", "Title", "Script", "Email", "UncommonHeaders", "HTTPServer"}


def split_top_level(line: str) -> list:
    """Split 'A[x], B[y, z]' on commas that are not inside brackets."""
    parts, depth, cur = [], 0, ""
    for ch in line:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth = max(depth - 1, 0)
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


class WhatWebModule(ExternalToolModule):
    key = "whatweb"
    tool = "whatweb"
    title = "WhatWeb"
    description = "Website fingerprinting"

    def build_command(self, ctx: Context, path: str, res: ModuleResult) -> list:
        cfg = ctx.profile["whatweb"]
        json_path = ctx.raw("whatweb.json")
        if json_path.exists():
            json_path.unlink()  # WhatWeb appends to existing logs
        res.raw_file = "raw/whatweb.json"
        return [path, "-a", str(cfg["aggression"]), "--color=never",
                f"--log-json={json_path}", "-U", ctx.user_agent, ctx.base_url]

    def format_line(self, ctx: Context, line: str) -> list:
        if "[" not in line:
            return [(line, ui.DIM)]
        parts = split_top_level(line)
        shown = [(parts[0], ui.WHITE)] if parts else []
        shown += [("  " + p, None) for p in parts[1:]]
        return shown

    def parse(self, ctx: Context, res: ModuleResult, lines: list) -> None:
        techs: dict = {}
        status = None
        for rec in load_json_flexible(ctx.raw("whatweb.json")):
            status = status or rec.get("http_status")
            for name, info in (rec.get("plugins") or {}).items():
                if not isinstance(info, dict):
                    continue
                version = ", ".join(str(v) for v in info.get("version", []) if v)
                detail = ", ".join(str(v) for v in info.get("string", []) if v)[:160]
                techs.setdefault(name, {"name": name, "version": version, "detail": detail})

        if not techs:  # fallback: parse the text line
            for line in lines:
                for name, value in re.findall(r"([A-Za-z0-9_.\-]+)\[([^\]]*)\]", line):
                    if name not in ("200", "301", "302", "404"):
                        techs.setdefault(name, {"name": name, "version": "", "detail": value[:160]})

        tech_list = sorted(techs.values(), key=lambda t: (t["name"] in NOISE, t["name"].lower()))
        res.data.update(technologies=tech_list, count=len(tech_list), http_status=status)
        if not tech_list:
            return
        names = [t["name"] for t in tech_list if t["name"] not in NOISE]
        res.add("info", f"{len(tech_list)} technologies fingerprinted",
                ", ".join(names[:25]), ctx.base_url)
        for t in tech_list:
            if t["version"] and t["name"] not in NOISE:
                res.add("info", f"Technology version detected: {t['name']} {t['version']}",
                        t["detail"], ctx.base_url)
            if t["name"] in ("X-Powered-By", "PoweredBy"):
                res.add("low", f"Technology disclosure via {t['name']}",
                        t["detail"] or t["version"], ctx.base_url)
