"""Nuclei: template-based vulnerability scanning.

Privacy/safety defaults: no interactsh (out-of-band) traffic to third-party servers unless
--oob is given, no update checks during a scan, and DoS-tagged templates are excluded.
"""
from __future__ import annotations

import json

from .. import dependencies as dep
from .. import ui
from ..models import ModuleResult
from .base import Context, ExternalToolModule, same_host

MAX_TARGETS = 200
SEV_COLOR = {"critical": ui.SEV_STYLE["critical"][0], "high": ui.SEV_STYLE["high"][0],
             "medium": ui.SEV_STYLE["medium"][0], "low": ui.SEV_STYLE["low"][0]}


def _loads(line: str):
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        data = json.loads(line)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        return None


class NucleiModule(ExternalToolModule):
    key = "nuclei"
    tool = "nuclei"
    title = "Nuclei"
    description = "Template-based vulnerability scan"

    def build_command(self, ctx: Context, path: str, res: ModuleResult) -> list:
        cfg = ctx.profile["nuclei"]
        out_file = ctx.raw("nuclei.jsonl")
        if out_file.exists():
            out_file.unlink()
        res.raw_file = "raw/nuclei.jsonl"

        target_args = ["-u", ctx.base_url]
        if cfg.get("use_endpoints"):
            katana = ctx.results.get("katana")
            endpoints = [u for u in (katana.data.get("endpoints", []) if katana else [])
                         if same_host(u, ctx.target.host)]
            if endpoints:
                targets = [ctx.base_url] + [u for u in endpoints if u.rstrip("/") != ctx.base_url][:MAX_TARGETS]
                list_file = ctx.raw("nuclei_targets.txt")
                list_file.write_text("\n".join(targets) + "\n")
                target_args = ["-l", str(list_file)]
                ctx.say("nuclei", f"scanning {len(targets)} crawled endpoints", ui.GREY)

        cmd = [path, *target_args, "-jsonl", "-silent", "-nc",
               "-severity", cfg["severity"], "-rl", str(cfg["rate"]), "-c", str(cfg["concurrency"]),
               "-timeout", "10", "-H", f"User-Agent: {ctx.user_agent}", "-o", str(out_file)]
        flags = [("-duc",), ("-exclude-tags", "dos")]
        if not ctx.opts.get("oob"):
            flags.append(("-ni",))
        cmd += dep.optional_flags("nuclei", *flags)
        return cmd

    def format_line(self, ctx: Context, line: str) -> list:
        data = _loads(line)
        if data is None:
            return [(line, ui.DIM)]
        info = data.get("info") or {}
        sev = str(info.get("severity", "info")).lower()
        text = f"[{sev.upper()}] {data.get('template-id', '?')}  {info.get('name', '')}  @ {data.get('matched-at', '')}"
        return [(text, SEV_COLOR.get(sev, ui.STEEL))]

    def parse(self, ctx: Context, res: ModuleResult, lines: list) -> None:
        seen = set()
        records = [d for d in (_loads(l) for l in lines) if d]
        if not records:  # fall back to the output file
            try:
                records = [d for d in (_loads(l) for l in ctx.raw("nuclei.jsonl").read_text().splitlines()) if d]
            except OSError:
                records = []
        for d in records:
            info = d.get("info") or {}
            key = (d.get("template-id"), d.get("matched-at"), d.get("matcher-name"))
            if key in seen:
                continue
            seen.add(key)
            sev = str(info.get("severity", "info")).lower()
            bits = []
            if info.get("description"):
                bits.append(str(info["description"]).strip())
            if d.get("matcher-name"):
                bits.append(f"matcher: {d['matcher-name']}")
            if d.get("extracted-results"):
                bits.append("extracted: " + ", ".join(map(str, d["extracted-results"]))[:200])
            cls = info.get("classification") or {}
            ids = cls.get("cve-id") or []
            if ids:
                bits.append("CVE: " + ", ".join(ids if isinstance(ids, list) else [ids]))
            if cls.get("cvss-score"):
                bits.append(f"CVSS {cls['cvss-score']}")
            refs = info.get("reference") or []
            ref = refs[0] if isinstance(refs, list) and refs else (refs if isinstance(refs, str) else "")
            title = f"{info.get('name', d.get('template-id', 'Nuclei finding'))} [{d.get('template-id', '')}]"
            res.add(sev, title, " | ".join(bits), d.get("matched-at") or d.get("host", ""), ref)
        res.data["count"] = len(seen)
