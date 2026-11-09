"""Katana: endpoint crawling, restricted to the target host."""
from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from .. import dependencies as dep
from .. import ui
from ..models import ModuleResult
from .base import Context, ExternalToolModule, classify_path, same_host

MAX_STORED = 5000
MAX_INTERESTING = 40


class KatanaModule(ExternalToolModule):
    key = "katana"
    tool = "katana"
    title = "Katana"
    description = "Endpoint crawling"

    def build_command(self, ctx: Context, path: str, res: ModuleResult) -> list:
        cfg = ctx.profile["katana"]
        out_file = ctx.raw("katana.txt")
        if out_file.exists():
            out_file.unlink()
        res.raw_file = "raw/katana.txt"
        cmd = [path, "-u", ctx.base_url, "-d", str(cfg["depth"]), "-silent", "-nc",
               "-rl", str(cfg["rate"]), "-c", str(cfg["concurrency"]), "-timeout", "10",
               "-ct", f"{cfg['duration']}s", "-H", f"User-Agent: {ctx.user_agent}",
               "-o", str(out_file)]
        # Optional flags are only added when the installed version supports them.
        cmd += dep.optional_flags(
            "katana",
            ("-fs", "fqdn"),                      # never leave the target host
            ("-jc",),                             # parse JavaScript for endpoints
            ("-kf", "robotstxt,sitemapxml"),      # known files
            ("-ef", "png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,css,mp4,mp3"),
        )
        return cmd

    def format_line(self, ctx: Context, line: str) -> list:
        if not line.startswith(("http://", "https://")):
            return [(line, ui.DIM)]
        hit = classify_path(line)
        if hit and hit[0] in ("critical", "high", "medium", "low"):
            return [(line, ui.ORANGE)]
        return [(line, ui.WHITE if "?" in line else None)]

    def parse(self, ctx: Context, res: ModuleResult, lines: list) -> None:
        seen = []
        for line in lines:
            url = line.strip().split()[0] if line.strip() else ""
            if url.startswith(("http://", "https://")) and same_host(url, ctx.target.host) \
                    and url not in seen:
                seen.append(url)
        urls = seen
        params, with_params, js_files = set(), 0, 0
        for url in urls:
            parts = urlsplit(url)
            if parts.query:
                with_params += 1
                params.update(parse_qs(parts.query, keep_blank_values=True).keys())
            if parts.path.lower().endswith(".js"):
                js_files += 1

        res.data.update(
            count=len(urls), endpoints=sorted(urls)[:MAX_STORED],
            with_params=with_params, parameters=sorted(params)[:200], js_files=js_files,
            truncated=len(urls) > MAX_STORED,
        )
        if not urls:
            return
        res.add("info", f"{len(urls)} endpoints discovered",
                f"{with_params} with query parameters, {len(params)} unique parameter names, "
                f"{js_files} JavaScript files.", ctx.base_url)
        added = 0
        for url in sorted(urls):
            hit = classify_path(url)
            if hit and added < MAX_INTERESTING:
                res.add(hit[0], f"Interesting endpoint: {hit[1]}", url=url)
                added += 1
