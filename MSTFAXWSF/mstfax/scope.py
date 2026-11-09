"""Authorization guard.

A target may only be scanned when it is
  1. listed in the user's scope file (~/.mstfaxwsf/authorized_targets.txt), or
  2. a loopback/private-network address or a lab-style host name, or
  3. a well-known intentionally vulnerable public test site.

On top of that, every interactive scan requires a typed confirmation and every
decision is written to an audit log. This is a safety net for honest operators,
not a legal substitute: you remain responsible for having permission.
"""
from __future__ import annotations

import getpass
import ipaddress
import json
import socket
import sys
from dataclasses import dataclass
from typing import Optional

from . import ui
from .config import AUDIT_LOG, SCOPE_FILE, ensure_dirs
from .models import now_iso

# Public sites that exist specifically to be scanned (verify they are still live/allowed).
LAB_SITES = {
    "testphp.vulnweb.com": "Acunetix public test site",
    "testasp.vulnweb.com": "Acunetix public test site",
    "testaspnet.vulnweb.com": "Acunetix public test site",
    "testhtml5.vulnweb.com": "Acunetix public test site",
    "rest.vulnweb.com": "Acunetix public test site",
    "demo.testfire.net": "IBM AltoroJ demo bank",
    "zero.webappsecurity.com": "Micro Focus demo site",
}
LAB_HOSTNAMES = {"localhost"}
LAB_SUFFIXES = (".localhost", ".local", ".lab", ".test", ".htb", ".thm", ".vm")
LAB_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12",
              "192.168.0.0/16", "fc00::/7")
]

CONFIRM_PHRASE = "AUTHORIZED"


@dataclass
class Decision:
    allowed: bool
    category: str  # scope-file | lab-site | lab-network | lab-hostname | denied
    reason: str
    entry: str = ""


@dataclass
class ScopeEntry:
    pattern: str
    note: str


# --- scope file ------------------------------------------------------------
def load_scope() -> list:
    entries = []
    if not SCOPE_FILE.exists():
        return entries
    for raw in SCOPE_FILE.read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pattern, _, note = line.partition("#")
        pattern = pattern.strip().lower()
        if pattern:
            entries.append(ScopeEntry(pattern, note.strip()))
    return entries


def _valid_pattern(pattern: str) -> bool:
    p = pattern.lower()
    if "/" in p:
        try:
            ipaddress.ip_network(p, strict=False)
            return True
        except ValueError:
            return False
    try:
        ipaddress.ip_address(p)
        return True
    except ValueError:
        pass
    body = p[2:] if p.startswith("*.") else p
    return bool(body) and "." in body and all(
        part and all(c.isalnum() or c in "-_" for c in part) for part in body.split(".")
    )


def add_scope(pattern: str, note: str, include_subdomains: bool = False) -> list:
    pattern = pattern.strip().lower().rstrip(".")
    if not _valid_pattern(pattern):
        raise ValueError("Use a domain (example.com), wildcard (*.example.com), IP or CIDR.")
    if len(note.strip()) < 5:
        raise ValueError("A short authorization note is required (e.g. 'My own site').")
    ensure_dirs()
    added = [pattern]
    if include_subdomains and not pattern.startswith("*.") and "/" not in pattern:
        try:
            ipaddress.ip_address(pattern)
        except ValueError:
            added.append("*." + pattern)
    with SCOPE_FILE.open("a") as fh:
        if SCOPE_FILE.stat().st_size == 0:
            fh.write("# MSTFAXWSF authorized targets - one per line: pattern  # note\n")
        for item in added:
            fh.write(f"{item}  # {note.strip()} (added {now_iso()} by {getpass.getuser()})\n")
    return added


def remove_scope(pattern: str) -> int:
    pattern = pattern.strip().lower()
    if not SCOPE_FILE.exists():
        return 0
    kept, removed = [], 0
    for raw in SCOPE_FILE.read_text(errors="replace").splitlines():
        head = raw.split("#", 1)[0].strip().lower()
        if head == pattern:
            removed += 1
        else:
            kept.append(raw)
    SCOPE_FILE.write_text("\n".join(kept) + ("\n" if kept else ""))
    return removed


# --- matching --------------------------------------------------------------
def _is_ip(host: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _matches(pattern: str, host: str) -> bool:
    if "/" in pattern:
        ip = _is_ip(host)
        try:
            return bool(ip and ip in ipaddress.ip_network(pattern, strict=False))
        except ValueError:
            return False
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host != pattern[2:]
    return host == pattern


def check_target(host: str) -> Decision:
    host = host.lower().rstrip(".")
    for entry in load_scope():
        if _matches(entry.pattern, host):
            return Decision(True, "scope-file", f"Listed in scope file ({entry.pattern})",
                            entry.pattern)
    ip = _is_ip(host)
    if ip is not None:
        for net in LAB_NETWORKS:
            if ip.version == net.version and ip in net:
                return Decision(True, "lab-network", f"Loopback/private lab network ({net})")
    if host in LAB_HOSTNAMES:
        return Decision(True, "lab-hostname", "Local host")
    if host in LAB_SITES:
        return Decision(True, "lab-site", f"Public test site: {LAB_SITES[host]}")
    for suffix in LAB_SUFFIXES:
        if host.endswith(suffix):
            return Decision(True, "lab-hostname", f"Lab-style host name ({suffix})")
    return Decision(False, "denied", "Not in scope file and not a recognised lab target")


# --- audit -----------------------------------------------------------------
def audit(event: str, **fields) -> None:
    try:
        ensure_dirs()
        record = {"time": now_iso(), "user": getpass.getuser(), "host": socket.gethostname(),
                  "event": event, **fields}
        with AUDIT_LOG.open("a") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass


# --- interactive authorization --------------------------------------------
def _typed_confirmation() -> bool:
    ui.out()
    ui.out(f"   {ui.paint('You must own this target or hold explicit written permission to test it.', ui.WHITE)}")
    ui.out(f"   {ui.paint('Unauthorized scanning can be illegal and may disrupt services.', ui.GREY)}")
    answer = ui.ask(f"Type {ui.paint(CONFIRM_PHRASE, ui.RED, True)} to continue")
    return answer.strip().upper() == CONFIRM_PHRASE


def authorize(host: str, assume_yes: bool = False):
    """Return (allowed, authorization_record). Never bypassed by --yes for out-of-scope hosts."""
    decision = check_target(host)
    interactive = sys.stdin.isatty()
    record = {"target": host, "scope_category": decision.category,
              "scope_reason": decision.reason, "scope_entry": decision.entry,
              "operator": getpass.getuser(), "time": now_iso(), "attestation": ""}

    ui.rule("AUTHORIZATION CHECK")
    if not decision.allowed:
        ui.err(f"{host} is not an authorized target.")
        ui.dim("It is not in your scope file and is not a recognised lab target.")
        if not interactive or assume_yes:
            ui.dim(f"Add it first:  mstfaxwsf scope add {host} --note \"why you may test it\"")
            audit("scan_denied", target=host, reason=decision.reason)
            return False, record
        ui.dim("If you own it or have written permission, you can add it to your scope file now.")
        if not ui.confirm("Add this target to your authorized scope?", default=False):
            audit("scan_denied", target=host, reason="operator declined scope add")
            return False, record
        note = ui.ask("Authorization reference (e.g. 'my own site', 'pentest SOW #42')")
        try:
            if not _typed_confirmation():
                ui.err("Confirmation phrase did not match. Scan cancelled.")
                audit("scan_denied", target=host, reason="confirmation failed")
                return False, record
            added = add_scope(host, note)
        except ValueError as exc:
            ui.err(str(exc))
            return False, record
        ui.ok(f"Added to scope: {', '.join(added)}")
        decision = check_target(host)
        record.update(scope_category=decision.category, scope_reason=decision.reason,
                      scope_entry=decision.entry, attestation="typed confirmation + scope entry",
                      authorization_note=note)
        audit("scope_added", target=host, note=note)
        return True, record

    ui.ok(f"{host}: {decision.reason}")
    if assume_yes:
        record["attestation"] = "--yes flag (target already in scope)"
    else:
        if not interactive:
            ui.err("Non-interactive session: pass --yes to confirm authorization for in-scope targets.")
            audit("scan_denied", target=host, reason="non-interactive without --yes")
            return False, record
        if not _typed_confirmation():
            ui.err("Confirmation phrase did not match. Scan cancelled.")
            audit("scan_denied", target=host, reason="confirmation failed")
            return False, record
        record["attestation"] = "typed confirmation"
    audit("scan_authorized", target=host, category=decision.category, reason=decision.reason)
    return True, record
