"""Command-line interface and beginner-friendly interactive menu."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, banner, dependencies, history, scope, ui
from .config import DEFAULT_PROFILE, MODULE_ORDER, PROFILES, ensure_dirs
from .engine import ScanEngine, print_summary
from .models import SEVERITIES
from .reporting import html_report, json_report
from .runner import run_streaming
from .target import TargetError, parse_target

SUBCOMMANDS = {"scan", "tools", "history", "scope", "report", "templates"}


# --- argument parsing -------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mstfaxwsf",
        description="MSTFAXWSF - web security assessment framework (authorized targets only).",
        epilog="Quick start:  mstfaxwsf example.com   |   mstfaxwsf   (interactive menu)")
    p.add_argument("--version", action="version", version=f"MSTFAXWSF {__version__}")
    p.add_argument("--no-banner", action="store_true", help="do not print the ASCII banner")
    p.add_argument("--no-color", action="store_true", help="disable colours")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan a domain, IP or URL (the default action)")
    s.add_argument("target", help="domain, IP or http(s) URL, e.g. example.com")
    s.add_argument("-p", "--profile", choices=list(PROFILES), default=DEFAULT_PROFILE)
    s.add_argument("-m", "--modules", help=f"comma-separated subset of: {','.join(MODULE_ORDER)}")
    s.add_argument("--skip", help="comma-separated modules to skip")
    s.add_argument("-w", "--wordlist", help="custom wordlist for FFUF")
    s.add_argument("--user-agent", help="override the User-Agent sent by all tools")
    s.add_argument("--oob", action="store_true", help="allow Nuclei out-of-band (interactsh) checks")
    s.add_argument("-q", "--quiet", action="store_true", help="hide live tool output")
    s.add_argument("-y", "--yes", action="store_true",
                   help="skip the typed confirmation (target must already be in scope)")

    t = sub.add_parser("tools", help="check (and optionally install) required tools")
    t.add_argument("--install", action="store_true", help="install missing tools")
    t.add_argument("-y", "--yes", action="store_true", help="do not ask before installing")

    h = sub.add_parser("history", help="list and manage past scans")
    h.add_argument("action", nargs="?", default="list", choices=["list", "show", "delete", "clear"])
    h.add_argument("ref", nargs="?", help="scan number (1 = newest) or id")

    sc = sub.add_parser("scope", help="manage authorized targets")
    sc.add_argument("action", choices=["list", "add", "remove", "check"])
    sc.add_argument("value", nargs="?", help="domain, *.domain, IP or CIDR")
    sc.add_argument("--note", default="", help="authorization reference (required for add)")
    sc.add_argument("--subdomains", action="store_true", help="also add *.domain")

    r = sub.add_parser("report", help="regenerate a report from a past scan")
    r.add_argument("ref", help="scan number (1 = newest) or id")
    r.add_argument("--format", choices=["html", "json", "both"], default="html")

    sub.add_parser("templates", help="update Nuclei templates")
    return p


# --- commands -----------------------------------------------------------------
def _csv(value):
    return [x.strip().lower() for x in value.split(",") if x.strip()] if value else []


def cmd_scan(args) -> int:
    try:
        target = parse_target(args.target)
    except TargetError as exc:
        ui.err(str(exc))
        return 2

    modules = _csv(args.modules) or list(MODULE_ORDER)
    unknown = [m for m in modules + _csv(args.skip) if m not in MODULE_ORDER]
    if unknown:
        ui.err(f"Unknown module(s): {', '.join(unknown)}. Choose from: {', '.join(MODULE_ORDER)}")
        return 2
    modules = [m for m in MODULE_ORDER if m in modules and m not in _csv(args.skip)]
    if not modules:
        ui.err("No modules selected.")
        return 2

    statuses = dependencies.detect_all()
    missing = [s.title for k, s in statuses.items() if not s.installed and k in modules]
    if missing:
        ui.warn(f"Not installed: {', '.join(missing)} (those steps will be skipped).")
        ui.dim("Install them with:  mstfaxwsf tools --install")

    allowed, authorization = scope.authorize(target.host, assume_yes=args.yes)
    if not allowed:
        return 3

    options = {"quiet": args.quiet, "wordlist": args.wordlist,
               "user_agent": args.user_agent, "oob": args.oob}
    try:
        engine = ScanEngine(target, args.profile, modules, options, authorization)
    except KeyError as exc:
        ui.err(str(exc))
        return 2
    session = engine.run()
    print_summary(session)
    return 130 if session.aborted else 0


def show_tools() -> dict:
    ui.rule("TOOL CHECK")
    statuses = dependencies.detect_all()
    rows = []
    for st in statuses.values():
        mark = ui.paint("✔ installed", ui.GREEN, True) if st.installed else ui.paint("✖ missing", ui.RED, True)
        rows.append((ui.paint(st.title, ui.WHITE, True), mark, st.version or "-", st.purpose, st.path or "-"))
    ui.table(["Tool", "Status", "Version", "Purpose", "Path"], rows, max_width=40)
    ui.out()
    for kind, found in dependencies.wordlist_status():
        ui.dim(f"wordlist ({kind}): {found or 'not found, bundled mini list will be used'}")
    ui.out()
    return statuses


def cmd_tools(args) -> int:
    statuses = show_tools()
    missing = [k for k, s in statuses.items() if not s.installed]
    if not missing:
        ui.ok("All 5 tools are installed.")
        return 0
    if not args.install:
        ui.warn(f"{len(missing)} tool(s) missing. Run:  mstfaxwsf tools --install")
        return 1
    for key in missing:
        dependencies.install(key, assume_yes=args.yes)
    ui.out()
    show_tools()
    return 0


def _history_table(entries: list) -> None:
    rows = []
    for i, e in enumerate(entries, 1):
        c = e["counts"]
        sev = " ".join(
            ui.paint(f"{s[0].upper()}{c.get(s, 0)}", ui.SEV_STYLE[s][0], ui.SEV_STYLE[s][1])
            for s in SEVERITIES)
        rows.append((str(i), e["started"][:16].replace("T", " "), e["target"], e["profile"],
                     f"{e['duration']:.0f}s", sev, "aborted" if e.get("aborted") else "done"))
    ui.table(["#", "Started", "Target", "Profile", "Time", "Findings (C/H/M/L/I)", "State"], rows)


def cmd_history(args) -> int:
    entries = history.list_entries()
    if args.action == "clear":
        if ui.confirm(f"Delete ALL {len(entries)} scans and their files?", default=False):
            ui.ok(f"Removed {history.clear()} scan(s).")
        return 0
    if args.action == "list" or not args.ref:
        if not entries:
            ui.info("No scans yet. Start one with:  mstfaxwsf example.com")
            return 0
        ui.rule("SCAN HISTORY")
        _history_table(entries)
        ui.out()
        ui.dim("Details: mstfaxwsf history show <#>    Regenerate: mstfaxwsf report <#>")
        return 0
    entry = history.resolve(args.ref)
    if not entry:
        ui.err(f"No scan matches '{args.ref}'.")
        return 1
    if args.action == "delete":
        if ui.confirm(f"Delete scan {entry['id']}?", default=False):
            history.delete(args.ref)
            ui.ok("Deleted.")
        return 0
    ui.rule(f"SCAN {entry['id']}")
    ui.panel([f"Target    {entry['target']}", f"Profile   {entry['profile']}",
              f"Started   {entry['started']}", f"Duration  {entry['duration']:.0f}s",
              "Modules   " + ", ".join(f"{k}:{v}" for k, v in entry["modules"].items()),
              f"HTML      {entry['report_html']}", f"JSON      {entry['report_json']}"])
    return 0


def cmd_scope(args) -> int:
    if args.action == "list":
        entries = scope.load_scope()
        ui.rule("AUTHORIZED TARGETS")
        if entries:
            ui.table(["Pattern", "Note"], [(e.pattern, e.note) for e in entries], max_width=80)
        else:
            ui.dim("Scope file is empty.")
        ui.out()
        ui.dim("Always allowed: localhost, loopback and private IP ranges, *.local/.lab/.test/.htb/.thm,")
        ui.dim("and public test sites: " + ", ".join(sorted(scope.LAB_SITES)))
        return 0
    if not args.value:
        ui.err("Give a value, e.g.  mstfaxwsf scope add example.com --note \"my own site\"")
        return 2
    if args.action == "check":
        d = scope.check_target(args.value)
        (ui.ok if d.allowed else ui.err)(f"{args.value}: {d.reason}")
        return 0 if d.allowed else 1
    if args.action == "add":
        note = args.note or (ui.ask("Authorization reference (why may you test this?)")
                             if sys.stdin.isatty() else "")
        try:
            added = scope.add_scope(args.value, note, args.subdomains)
        except ValueError as exc:
            ui.err(str(exc))
            return 2
        scope.audit("scope_added", target=args.value, note=note)
        ui.ok(f"Added: {', '.join(added)}")
        return 0
    removed = scope.remove_scope(args.value)
    (ui.ok if removed else ui.warn)(f"Removed {removed} entr{'y' if removed == 1 else 'ies'}.")
    return 0


def cmd_report(args) -> int:
    entry = history.resolve(args.ref)
    if not entry:
        ui.err(f"No scan matches '{args.ref}'.")
        return 1
    data = history.load_session_json(entry)
    if not data:
        ui.err("The saved JSON report is missing or unreadable.")
        return 1
    out = Path(entry["dir"])
    if args.format in ("html", "both"):
        ui.ok(f"HTML: {html_report.write(data, out / 'report.html')}")
    if args.format in ("json", "both"):
        ui.ok(f"JSON: {json_report.write(data, out / 'report.json')}")
    return 0


def cmd_templates(_args) -> int:
    path = dependencies.tool_path("nuclei")
    if not path:
        ui.err("Nuclei is not installed. Run:  mstfaxwsf tools --install")
        return 1
    ui.info("Updating Nuclei templates (requires internet)...")
    res = run_streaming([path, "-update-templates"], on_line=lambda l: ui.live("nuclei", l), timeout=600)
    (ui.ok if res.returncode == 0 else ui.err)("Templates updated." if res.returncode == 0 else "Update failed.")
    return 0 if res.returncode == 0 else 1


# --- interactive menu ---------------------------------------------------------------
def _menu_scan() -> None:
    ui.rule("NEW SCAN")
    ui.dim("Enter a domain, IP or URL. Everything else is automatic.")
    raw = ui.ask("Target (e.g. example.com)")
    if not raw:
        return
    names = list(PROFILES)
    for i, name in enumerate(names, 1):
        ui.out(f"   {ui.paint(f'[{i}]', ui.RED, True)} {name.ljust(9)} {ui.paint(PROFILES[name]['description'], ui.GREY)}")
    choice = ui.ask("Profile", "2")
    profile = names[int(choice) - 1] if choice.isdigit() and 1 <= int(choice) <= len(names) else DEFAULT_PROFILE
    ns = argparse.Namespace(target=raw, profile=profile, modules=None, skip=None, wordlist=None,
                            user_agent=None, oob=False, quiet=False, yes=False)
    cmd_scan(ns)


def _menu_history() -> None:
    cmd_history(argparse.Namespace(action="list", ref=None))
    entries = history.list_entries()
    if not entries:
        return
    ref = ui.ask("Enter a scan number to view (blank to go back)")
    if ref:
        cmd_history(argparse.Namespace(action="show", ref=ref))


def _menu_scope() -> None:
    cmd_scope(argparse.Namespace(action="list", value=None, note="", subdomains=False))
    if ui.confirm("Add an authorized target?", default=False):
        value = ui.ask("Domain, *.domain, IP or CIDR")
        if value:
            cmd_scope(argparse.Namespace(action="add", value=value, note="", subdomains=ui.confirm(
                "Include subdomains?", default=False)))


def _menu_help() -> None:
    ui.rule("HELP")
    for line in (
        "1. Pick 'New scan' and type a domain. Recon, fingerprinting, crawling, directory",
        "   discovery, Nikto and Nuclei run one after another with live output.",
        "2. Only authorized targets are accepted: localhost, private lab IPs, public test sites,",
        "   or anything you add to your scope file with a written authorization note.",
        "3. Ctrl+C skips the running tool; press it twice quickly to abort the scan.",
        "4. Reports (HTML + JSON) are saved under ~/.mstfaxwsf/scans/<scan-id>/.",
        "5. CLI shortcut:  mstfaxwsf example.com -p quick",
    ):
        ui.out("  " + ui.paint(line, ui.GREY))
    ui.out()


def interactive() -> int:
    actions = {
        "1": _menu_scan,
        "2": lambda: cmd_tools(argparse.Namespace(install=ui.confirm("Install missing tools?", False), yes=False)),
        "3": _menu_history,
        "4": _menu_scope,
        "5": lambda: cmd_templates(None),
        "6": _menu_help,
    }
    while True:
        ui.out()
        for key, label in (("1", "New scan"), ("2", "Check / install tools"), ("3", "Scan history"),
                           ("4", "Authorized targets (scope)"), ("5", "Update Nuclei templates"),
                           ("6", "Help"), ("0", "Exit")):
            ui.out(f"   {ui.paint(f'[{key}]', ui.RED, True)} {label}")
        ui.out()
        choice = ui.ask("Select").strip()
        if choice in ("0", "q", "exit", "quit"):
            return 0
        action = actions.get(choice)
        if action is None:
            ui.warn("Choose a number from the menu.")
            continue
        try:
            action()
        except KeyboardInterrupt:
            ui.out()
            ui.warn("Cancelled.")


# --- entry point -------------------------------------------------------------------
def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Global display flags may appear anywhere, so extract them before sub-command parsing.
    no_banner = "--no-banner" in argv
    no_color = "--no-color" in argv
    argv = [a for a in argv if a not in ("--no-banner", "--no-color")]
    # Shortcut: `mstfaxwsf example.com [options]` means `mstfaxwsf scan example.com [options]`.
    if argv and argv[0] not in SUBCOMMANDS and argv[0] not in ("-h", "--help", "--version"):
        if not any(a in SUBCOMMANDS for a in argv):
            argv = ["scan"] + argv

    parser = build_parser()
    args = parser.parse_args(argv)
    if no_color or args.no_color:
        ui.disable_color()
    ensure_dirs()
    dependencies.ensure_paths()
    if not (no_banner or args.no_banner):
        banner.show(compact=args.command in ("history", "scope", "report"))

    try:
        if args.command is None:
            return interactive()
        handler = {"scan": cmd_scan, "tools": cmd_tools, "history": cmd_history, "scope": cmd_scope,
                   "report": cmd_report, "templates": cmd_templates}[args.command]
        return handler(args)
    except KeyboardInterrupt:
        ui.clear_status()
        ui.out()
        ui.warn("Interrupted.")
        return 130
