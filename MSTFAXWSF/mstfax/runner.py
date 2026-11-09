"""Run external tools with live line streaming, timeouts and clean interruption."""
from __future__ import annotations

import os
import re
import select
import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .ui import ANSI_RE

_SPLIT_RE = re.compile(rb"\r\n|\n|\r")


@dataclass
class RunResult:
    returncode: Optional[int] = None
    duration: float = 0.0
    timed_out: bool = False
    interrupted: bool = False
    error: str = ""
    lines: list = field(default_factory=list)


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return
    for sig, wait in ((signal.SIGTERM, 3.0), (signal.SIGKILL, 2.0)):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def run_streaming(
    cmd: list,
    on_line: Optional[Callable[[str], None]] = None,
    timeout: Optional[float] = None,
    cwd: Optional[str] = None,
    on_idle: Optional[Callable[[float], None]] = None,
) -> RunResult:
    """Run *cmd* (never through a shell) and stream cleaned output lines to *on_line*.

    The child runs in its own session, so Ctrl+C is delivered to us only; we then
    terminate the whole child process group and report ``interrupted=True``.
    """
    result = RunResult()
    start = time.monotonic()
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            cwd=cwd, bufsize=0, start_new_session=True,
        )
    except (OSError, ValueError) as exc:
        result.error = f"Could not start {cmd[0]}: {exc}"
        return result

    fd = proc.stdout.fileno()
    buf = b""

    def emit(raw: bytes) -> None:
        text = ANSI_RE.sub("", raw.decode("utf-8", errors="replace")).rstrip()
        if not text.strip():
            return
        result.lines.append(text)
        if on_line:
            on_line(text)

    try:
        while True:
            if timeout and time.monotonic() - start > timeout:
                result.timed_out = True
                _kill_group(proc)
                break
            ready, _, _ = select.select([fd], [], [], 1.0)
            if ready:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                buf += chunk
                parts = _SPLIT_RE.split(buf)
                buf = parts.pop()
                for part in parts:
                    emit(part)
            else:
                if proc.poll() is not None:
                    break
                if on_idle:
                    on_idle(time.monotonic() - start)
        if buf:
            emit(buf)
    except KeyboardInterrupt:
        result.interrupted = True
        _kill_group(proc)
    finally:
        try:
            proc.stdout.close()
        except OSError:
            pass
    try:
        result.returncode = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        result.returncode = proc.returncode
    result.duration = time.monotonic() - start
    return result
