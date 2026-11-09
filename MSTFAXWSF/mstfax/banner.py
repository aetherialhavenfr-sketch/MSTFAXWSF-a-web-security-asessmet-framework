"""MSTFAXWSF ASCII branding: big block letters with a red -> dark-red gradient."""
from __future__ import annotations

from . import __version__, ui

# "ANSI Shadow" style glyphs, 6 rows tall.
GLYPHS = {
    "M": ["███╗   ███╗",
          "████╗ ████║",
          "██╔████╔██║",
          "██║╚██╔╝██║",
          "██║ ╚═╝ ██║",
          "╚═╝     ╚═╝"],
    "S": ["███████╗",
          "██╔════╝",
          "███████╗",
          "╚════██║",
          "███████║",
          "╚══════╝"],
    "T": ["████████╗",
          "╚══██╔══╝",
          "   ██║   ",
          "   ██║   ",
          "   ██║   ",
          "   ╚═╝   "],
    "F": ["███████╗",
          "██╔════╝",
          "█████╗  ",
          "██╔══╝  ",
          "██║     ",
          "╚═╝     "],
    "A": [" █████╗ ",
          "██╔══██╗",
          "███████║",
          "██╔══██║",
          "██║  ██║",
          "╚═╝  ╚═╝"],
    "X": ["██╗  ██╗",
          "╚██╗██╔╝",
          " ╚███╔╝ ",
          " ██╔██╗ ",
          "██╔╝ ██╗",
          "╚═╝  ╚═╝"],
    "W": ["██╗    ██╗",
          "██║    ██║",
          "██║ █╗ ██║",
          "██║███╗██║",
          "╚███╔███╔╝",
          " ╚══╝╚══╝ "],
}

WORD = "MSTFAXWSF"


def banner_rows() -> list:
    rows = []
    for r in range(6):
        row = ""
        for letter in WORD:
            glyph = GLYPHS[letter]
            width = max(len(g) for g in glyph)
            row += glyph[r].ljust(width)
        rows.append(row.rstrip())
    return rows


def render() -> str:
    rows = banner_rows()
    if ui.term_width() < 80:  # compact fallback for narrow terminals
        return ui.gradient(" M S T F A X W S F ", ui.RED, ui.BLOOD, bold=True)
    if ui.COLOR_LEVEL == 0:
        return "\n".join(rows)
    width = max(len(r) for r in rows)
    height = len(rows)
    lines = []
    for r, row in enumerate(rows):
        buf = []
        for c, ch in enumerate(row):
            if ch == " ":
                buf.append(" ")
                continue
            t = 0.65 * (c / max(width - 1, 1)) + 0.35 * (r / max(height - 1, 1))
            color = ui.lerp_color(ui.RED, ui.BLOOD, t)
            if ch != "█":  # darken the "shadow" strokes for depth
                color = ui.lerp_color(color, (0, 0, 0), 0.45)
            buf.append(ui.fg(color) + ch)
        lines.append("\x1b[1m" + "".join(buf) + "\x1b[0m")
    return "\n".join(lines)


def show(compact: bool = False) -> None:
    ui.out()
    ui.out(render())
    if compact:
        ui.out()
        return
    ui.out()
    ui.out(ui.gradient("━" * min(ui.term_width(), 78), ui.RED, ui.BLOOD))
    ui.out("  " + ui.paint("Advanced Web Security Assessment Framework", ui.WHITE, True)
           + ui.paint(f"   v{__version__}", ui.DARK_RED, True))
    ui.out("  " + ui.paint("Katana  ▪  FFUF  ▪  WhatWeb  ▪  Nikto  ▪  Nuclei", ui.CRIMSON))
    ui.out("  " + ui.paint("⚠  Authorized targets and security labs only", ui.ORANGE))
    ui.out(ui.gradient("━" * min(ui.term_width(), 78), ui.RED, ui.BLOOD))
    ui.out()
