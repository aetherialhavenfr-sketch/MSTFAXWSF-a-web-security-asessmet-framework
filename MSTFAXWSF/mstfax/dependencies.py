"""Tool installation detection, version lookup, optional-flag probing and installer."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import ui
from .config import WORDLIST_CANDIDATES
from .runner import run_streaming


@dataclass(frozen=True)
class ToolSpec:
    key: str
    binary: str
    title: str
    purpose: str
    version_args: tuple
    help_args: tuple
    apt_pkg: Optional[str]
    go_pkg: Optional[str]


TOOLS = {
    "whatweb": ToolSpec("whatweb", "whatweb", "WhatWeb", "Website fingerprinting",
                        ("--version",), ("-h",), "whatweb", None),
    "katana": ToolSpec("katana", "katana", "Katana", "Endpoint crawling",
                       ("-version",), ("-h",), "katana",
                       "github.com/projectdiscovery/katana/cmd/katana@latest"),
    "ffuf": ToolSpec("ffuf", "ffuf", "FFUF", "Directory discovery",
                     ("-V",), ("-h",), "ffuf", "github.com/ffuf/ffuf/v2@latest"),
    "nikto": ToolSpec("nikto", "nikto", "Nikto", "Web server vulnerability scan",
                      ("-Version",), ("-Help",), "nikto", None),
    "nuclei": ToolSpec("nuclei", "nuclei", "Nuclei", "Template-based vulnerability scan",
                       ("-version",), ("-h",), "nuclei",
                       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
}

VERSION_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+)*(?:-[A-Za-z0-9.]+)?)")


@dataclass
class ToolStatus:
    key: str
    title: str
    purpose: str
    installed: bool
    path: str = ""
    version: str = ""


def ensure_paths() -> None:
    """Make sure go-installed binaries are on PATH for this process."""
    homes = {Path.home()}
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            homes.add(Path(pwd.getpwnam(sudo_user).pw_dir))
        except (ImportError, KeyError):
            pass
    extras = [h / "go" / "bin" for h in homes] + [h / ".local" / "bin" for h in homes]
    extras += [Path("/usr/local/go/bin"), Path("/usr/local/bin"), Path("/root/go/bin")]
    current = os.environ.get("PATH", "").split(os.pathsep)
    for p in extras:
        if p.is_dir() and str(p) not in current:
            current.append(str(p))
    os.environ["PATH"] = os.pathsep.join(current)


def tool_path(key: str) -> Optional[str]:
    return shutil.which(TOOLS[key].binary)


def _run_capture(cmd: list, timeout: int = 15) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              stdin=subprocess.DEVNULL, errors="replace")
        return ui.strip_ansi((proc.stdout or "") + "\n" + (proc.stderr or ""))
    except (OSError, subprocess.TimeoutExpired):
        return ""


def detect(key: str) -> ToolStatus:
    spec = TOOLS[key]
    path = tool_path(key)
    if not path:
        return ToolStatus(key, spec.title, spec.purpose, False)
    output = _run_capture([path, *spec.version_args])
    match = VERSION_RE.search(output)
    return ToolStatus(key, spec.title, spec.purpose, True, path, match.group(1) if match else "")


def detect_all() -> dict:
    return {key: detect(key) for key in TOOLS}


_HELP_CACHE: dict = {}


def supports(key: str, flag: str) -> bool:
    """True when the installed tool advertises *flag* in its help text."""
    if key not in _HELP_CACHE:
        path = tool_path(key)
        _HELP_CACHE[key] = _run_capture([path, *TOOLS[key].help_args]) if path else ""
    text = _HELP_CACHE[key]
    return bool(text) and re.search(rf"(?<![\w-]){re.escape(flag)}(?![\w-])", text) is not None


def optional_flags(key: str, *flags) -> list:
    """Build argument list for optional flags. Each item is ``(flag,)`` or ``(flag, value)``."""
    args: list = []
    for item in flags:
        if supports(key, item[0]):
            args.extend(item)
    return args


# --- wordlists --------------------------------------------------------------
def wordlist_status() -> list:
    rows = []
    for kind, paths in WORDLIST_CANDIDATES.items():
        found = next((p for p in paths if Path(p).is_file()), None)
        rows.append((kind, found))
    return rows


# --- installer --------------------------------------------------------------
def install_plan(key: str) -> list:
    spec = TOOLS[key]
    plan = []
    sudo = [] if hasattr(os, "geteuid") and os.geteuid() == 0 else ["sudo"]
    if spec.apt_pkg and shutil.which("apt-get") and (not sudo or shutil.which("sudo")):
        plan.append([*sudo, "apt-get", "install", "-y", spec.apt_pkg])
    if spec.go_pkg and shutil.which("go"):
        plan.append(["go", "install", "-v", spec.go_pkg])
    return plan


def install(key: str, assume_yes: bool = False) -> bool:
    spec = TOOLS[key]
    if tool_path(key):
        ui.ok(f"{spec.title} is already installed.")
        return True
    plan = install_plan(key)
    if not plan:
        ui.err(f"No automatic installer available for {spec.title}.")
        ui.dim(f"Kali:  sudo apt install {spec.apt_pkg or spec.binary}")
        if spec.go_pkg:
            ui.dim(f"Or install Go, then:  go install {spec.go_pkg}")
        return False
    for cmd in plan:
        ui.info(f"{spec.title}: {' '.join(cmd)}")
        if not assume_yes and not ui.confirm("Run this command?", default=True):
            continue
        res = run_streaming(cmd, on_line=lambda line: ui.live("install", line), timeout=900)
        ensure_paths()
        if res.returncode == 0 and tool_path(key):
            _HELP_CACHE.pop(key, None)
            ui.ok(f"{spec.title} installed.")
            return True
        ui.warn("That did not work, trying the next option..." if cmd is not plan[-1] else "Install failed.")
    return bool(tool_path(key))
