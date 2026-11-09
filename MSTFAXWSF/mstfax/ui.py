"""Terminal UI helpers: black/red palette, gradients, panels, tables and prompts.

Pure standard library. Colour is auto-detected (truecolor > 256 > none) and
disabled automatically when output is piped or NO_COLOR is set.
"""
from __future__ import annotations

import os
import re
import shutil
import sys

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

# --- palette ---------------------------------------------------------------
RED = (255, 38, 38)
CRIMSON = (205, 20, 36)
DARK_RED = (128, 8, 20)
BLOOD = (86, 0, 10)
WHITE = (236, 236, 236)
GREY = (150, 150, 150)
DIM = (98, 98, 98)
ORANGE = (255, 150, 30)
YELLOW = (240, 212, 70)
GREEN = (76, 214, 120)
STEEL = (110, 170, 220)

SEV_STYLE = {
    "critical": ((255, 30, 70), True),
    "high": ((255, 92, 48), True),
    "medium": ((255, 176, 32), False),
    "low": ((232, 220, 90), False),
    "info": (STEEL, False),
}

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _detect() -> int:
    if os.environ.get("NO_COLOR") or os.environ.get("MSTFAXWSF_NO_COLOR"):
        return 0
    if not sys.stdout.isatty():
        return 0
    if os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit"):
        return 2
    term = os.environ.get("TERM", "")
    if term == "dumb":
        return 0
    if "direct" in term:
        return 2
    return 1  # 256-colour fallback


COLOR_LEVEL = _detect()


def disable_color() -> None:
    global COLOR_LEVEL
    COLOR_LEVEL = 0


def _rgb_to_256(r: int, g: int, b: int) -> int:
    def q(v: int) -> int:
        return 0 if v < 48 else 1 if v < 115 else (v - 35) // 40

    return 16 + 36 * q(r) + 6 * q(g) + q(b)


def fg(rgb) -> str:
    if COLOR_LEVEL == 0 or rgb is None:
        return ""
    r, g, b = rgb
    if COLOR_LEVEL == 2:
        return f"\x1b[38;2;{r};{g};{b}m"
    return f"\x1b[38;5;{_rgb_to_256(r, g, b)}m"


def paint(text: str, rgb=None, bold: bool = False) -> str:
    if COLOR_LEVEL == 0 or (rgb is None and not bold):
        return text
    codes = ("\x1b[1m" if bold else "") + fg(rgb)
    return f"{codes}{text}\x1b[0m"


def lerp_color(c1, c2, t: float):
    t = max(0.0, min(1.0, t))
    return tuple(int(round(a + (b - a) * t)) for a, b in zip(c1, c2))


def gradient(text: str, c1=RED, c2=BLOOD, bold: bool = False) -> str:
    if COLOR_LEVEL == 0 or not text:
        return text
    n = max(len(text) - 1, 1)
    body = "".join(fg(lerp_color(c1, c2, i / n)) + ch for i, ch in enumerate(text))
    return ("\x1b[1m" if bold else "") + body + "\x1b[0m"


def sev_tag(severity: str) -> str:
    color, bold = SEV_STYLE.get(severity, (GREY, False))
    return paint(f"[{severity.upper()}]".ljust(10), color, bold)


# --- sizing / measuring ----------------------------------------------------
def term_width() -> int:
    return max(60, min(shutil.get_terminal_size((100, 24)).columns, 140))


def visible_len(text: str) -> int:
    return len(ANSI_RE.sub("", text))


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


# --- output ----------------------------------------------------------------
_status_on = False


def clear_status() -> None:
    global _status_on
    if _status_on:
        sys.stdout.write("\r\x1b[2K")
        sys.stdout.flush()
        _status_on = False


def out(msg: str = "") -> None:
    clear_status()
    print(msg, flush=True)


def status(msg: str) -> None:
    """Single-line in-place status (spinner / heartbeat). No-op when piped."""
    global _status_on
    if not sys.stdout.isatty():
        return
    msg = strip_ansi(msg)[: term_width() - 2]
    sys.stdout.write("\r\x1b[2K" + paint(msg, GREY))
    sys.stdout.flush()
    _status_on = True


def info(msg: str) -> None:
    out(f" {paint('[*]', CRIMSON, True)} {msg}")


def ok(msg: str) -> None:
    out(f" {paint('[+]', GREEN, True)} {msg}")


def warn(msg: str) -> None:
    out(f" {paint('[!]', ORANGE, True)} {msg}")


def err(msg: str) -> None:
    out(f" {paint('[x]', RED, True)} {paint(msg, RED)}")


def dim(msg: str) -> None:
    out(f"   {paint(msg, DIM)}")


def live(tool: str, text: str, color=None) -> None:
    """One line of live tool output, framed with a dark-red gutter."""
    text = text.replace("\t", "    ")
    room = term_width() - 14
    if len(text) > room:
        text = text[: room - 1] + "…"
    out(f"  {paint('│', DARK_RED)} {paint(tool.ljust(7), CRIMSON)} {paint(text, color or GREY)}")


def rule(title: str = "", char: str = "━") -> None:
    width = term_width()
    if title:
        label = f" {title} "
        left = char * 3
        right = char * max(width - len(left) - len(label), 0)
        out(paint(left, RED, True) + paint(label, WHITE, True) + gradient(right, CRIMSON, BLOOD))
    else:
        out(gradient(char * width, RED, BLOOD))


def panel(lines, title: str = "", color=DARK_RED) -> None:
    width = term_width()
    inner = width - 4
    if title:
        label = f" {title} "
        top = "╭─" + label + "─" * max(inner - len(label), 0) + "─╮"
        out(paint(top[:2], color) + paint(label, WHITE, True) + paint(top[2 + len(label):], color))
    else:
        out(paint("╭" + "─" * (width - 2) + "╮", color))
    for line in lines:
        pad = max(inner - visible_len(line), 0)
        out(f"{paint('│', color)} {line}{' ' * pad} {paint('│', color)}")
    out(paint("╰" + "─" * (width - 2) + "╯", color))


def _fit(cell: str, width: int) -> str:
    if visible_len(cell) <= width:
        return cell + " " * (width - visible_len(cell))
    plain = strip_ansi(cell)
    return plain[: max(width - 1, 1)] + "…"


def table(headers, rows, max_width: int = 48) -> None:
    widths = [visible_len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], min(visible_len(str(cell)), max_width))
    gap = "  "
    out("  " + gap.join(paint(h.ljust(w), RED, True) for h, w in zip(headers, widths)))
    out("  " + gap.join(paint("─" * w, DARK_RED) for w in widths))
    for row in rows:
        out("  " + gap.join(_fit(str(c), w) for c, w in zip(row, widths)))


# --- prompts ---------------------------------------------------------------
def _prompt(prompt: str, default: str = ""):
    """Read one line. Returns None when stdin is closed (EOF)."""
    suffix = paint(f" [{default}]", GREY) if default else ""
    sys.stdout.write(f" {paint('›', RED, True)} {prompt}{suffix}: ")
    sys.stdout.flush()
    try:
        value = input().strip()
    except EOFError:
        sys.stdout.write("\n")
        return None
    return value or default


def ask(prompt: str, default: str = "") -> str:
    value = _prompt(prompt, default)
    return default if value is None else value


def confirm(prompt: str, default: bool = False) -> bool:
    """Yes/no question. Closed stdin always means 'no', never the default."""
    value = _prompt(f"{prompt} ({'Y/n' if default else 'y/N'})")
    if value is None:
        return False
    if not value:
        return default
    return value.lower() in ("y", "yes")
