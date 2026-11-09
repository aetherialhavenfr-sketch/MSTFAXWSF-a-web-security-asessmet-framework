"""Central configuration: file locations, scan profiles and wordlist lookup."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from . import __version__

HOME = Path(os.environ.get("MSTFAXWSF_HOME", str(Path.home() / ".mstfaxwsf")))
SCANS_DIR = HOME / "scans"
HISTORY_FILE = HOME / "history.json"
SCOPE_FILE = HOME / "authorized_targets.txt"
AUDIT_LOG = HOME / "audit.log"

DATA_DIR = Path(__file__).resolve().parent / "data"
BUNDLED_WORDLIST = DATA_DIR / "mini_wordlist.txt"

# Honest, identifiable user agent so defenders can recognise the traffic.
USER_AGENT = f"MSTFAXWSF/{__version__} (authorized security assessment)"

# Execution order of the pipeline.
MODULE_ORDER = ["recon", "whatweb", "katana", "ffuf", "nikto", "nuclei"]

DEFAULT_PROFILE = "standard"

# Every profile keeps request rates conservative on purpose.
PROFILES = {
    "quick": {
        "description": "Fast overview, high/critical issues only (about 5-10 min)",
        "whatweb": {"aggression": 1, "timeout": 120},
        "katana": {"depth": 2, "rate": 50, "concurrency": 10, "duration": 60, "timeout": 150},
        "ffuf": {"rate": 50, "threads": 20, "maxtime": 120, "timeout": 180,
                 "wordlist": "mini", "extensions": ""},
        "nikto": {"maxtime": 120, "timeout": 200},
        "nuclei": {"severity": "high,critical", "rate": 50, "concurrency": 20,
                   "timeout": 600, "use_endpoints": False},
    },
    "standard": {
        "description": "Balanced coverage, medium and above (about 15-30 min)",
        "whatweb": {"aggression": 3, "timeout": 180},
        "katana": {"depth": 3, "rate": 100, "concurrency": 10, "duration": 120, "timeout": 300},
        "ffuf": {"rate": 100, "threads": 30, "maxtime": 300, "timeout": 420,
                 "wordlist": "common", "extensions": ""},
        "nikto": {"maxtime": 300, "timeout": 420},
        "nuclei": {"severity": "medium,high,critical", "rate": 100, "concurrency": 25,
                   "timeout": 900, "use_endpoints": False},
    },
    "deep": {
        "description": "Thorough, all severities, crawled endpoints fed to Nuclei (45+ min)",
        "whatweb": {"aggression": 3, "timeout": 240},
        "katana": {"depth": 4, "rate": 150, "concurrency": 15, "duration": 300, "timeout": 600},
        "ffuf": {"rate": 150, "threads": 40, "maxtime": 900, "timeout": 1000,
                 "wordlist": "large", "extensions": ".php,.html,.txt,.bak,.old"},
        "nikto": {"maxtime": 900, "timeout": 1000},
        "nuclei": {"severity": "low,medium,high,critical", "rate": 150, "concurrency": 30,
                   "timeout": 2400, "use_endpoints": True},
    },
}

WORDLIST_CANDIDATES = {
    "common": [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/dirb/wordlists/common.txt",
    ],
    "large": [
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    ],
}


def ensure_dirs() -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(HOME, 0o700)
    except OSError:
        pass


def resolve_wordlist(kind: str, override: Optional[str] = None) -> Path:
    """Pick a wordlist: user override > system list for the profile > bundled list."""
    if override:
        p = Path(override).expanduser()
        if not p.is_file():
            raise FileNotFoundError(f"Wordlist not found: {p}")
        return p
    pools = []
    if kind == "large":
        pools = WORDLIST_CANDIDATES["large"] + WORDLIST_CANDIDATES["common"]
    elif kind == "common":
        pools = WORDLIST_CANDIDATES["common"]
    for candidate in pools:
        if Path(candidate).is_file():
            return Path(candidate)
    return BUNDLED_WORDLIST
