"""Nikto: classic web server checks. Nikto does not grade findings, so severity is heuristic."""
from __future__ import annotations

import re

from .. import dependencies as dep
from .. import ui
from ..models import ModuleResult
from .base import Context, ExternalToolModule

META_PREFIXES = (
    "Target IP:", "Target Hostname:", "Target Port:", "Start Time:", "End Time:",
    "SSL Info:", "Scan terminated:", "No CGI Directories", "Multiple IPs found",
    "Platform:", "Using Encoding:", "Retrying", "ERROR:",
)
SUMMARY_RE = re.compile(r"\d+ requests?:|host\(s\) tested|item\(s\) reported", re.I)
PATH_RE = re.compile(r"^(/[^\s:]*):")

# (regex, severity) - first match wins.
SEVERITY_RULES = [
    (re.compile(r"remote code|command exec|shellshock|backdoor|sql injection|"
                r"directory traversal|remote file inclusion|default (credential|password)|"
                r"arbitrary (file|code)", re.I), "high"),
    (re.compile(r"cve-\d{4}-\d+|osvdb-\d+|vulnerab|cross.?site|xss|outdated|end.of.life|"
                r"directory (indexing|listing)|allowed http methods:.*(put|delete|trace)|"
                r"\bputs?\b.*enabled|information disclosure|phpinfo|\.git|\.env|backup", re.I), "medium"),
    (re.compile(r"header.*(not (present|set|defined)|missing)|not set|"
                r"cookie|etag|inode|default file|may be|allowed http methods|uncommon header", re.I), "low"),
]


def rate(message: str) -> str:
    for pattern, severity in SEVERITY_RULES:
        if pattern.search(message):
            return severity
    return "info"


class NiktoModule(ExternalToolModule):
    key = "nikto"
    tool = "nikto"
    title = "Nikto"
    description = "Web server vulnerability scan"

    def build_command(self, ctx: Context, path: str, res: ModuleResult) -> list:
        cfg = ctx.profile["nikto"]
        out_file = ctx.raw("nikto.json")
        if out_file.exists():
            out_file.unlink()
        res.raw_file = "raw/nikto.log"
        cmd = [path, "-h", ctx.base_url, "-maxtime", f"{cfg['maxtime']}s"]
        cmd += dep.optional_flags(
            "nikto",
            ("-nointeractive",),
            ("-useragent", ctx.user_agent),
            ("-Format", "json"),
            ("-output", str(out_file)),
        )
        return cmd

    def format_line(self, ctx: Context, line: str) -> list:
        if not line.startswith("+"):
            return [(line, ui.DIM)]
        body = line[1:].strip()
        if body.startswith(META_PREFIXES) or SUMMARY_RE.search(body):
            return [(line, ui.DIM)]
        sev = rate(body)
        color = {"high": ui.RED, "medium": ui.ORANGE, "low": ui.YELLOW}.get(sev, ui.GREY)
        return [(line, color)]

    def parse(self, ctx: Context, res: ModuleResult, lines: list) -> None:
        items = 0
        banner = ""
        for line in lines:
            if not line.startswith("+"):
                continue
            body = line[1:].strip()
            if body.startswith("Server:"):
                banner = body.split(":", 1)[1].strip()
                res.add("info", "Server banner", banner, ctx.base_url)
                continue
            if body.startswith(META_PREFIXES) or SUMMARY_RE.search(body) or not body:
                continue
            m = PATH_RE.match(body)
            url = ctx.base_url + m.group(1) if m else ctx.base_url
            message = body[m.end():].strip() if m else body
            ref = ""
            ref_match = re.search(r"See:\s*(\S+)", message)
            if ref_match:
                ref = ref_match.group(1)
                message = message[:ref_match.start()].strip()
            res.add(rate(message), message[:200], detail=message, url=url, reference=ref)
            items += 1
        res.data.update(count=items, banner=banner)
