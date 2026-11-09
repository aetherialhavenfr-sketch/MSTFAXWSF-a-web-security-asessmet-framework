#!/usr/bin/env python3
"""MSTFAXWSF launcher.  Usage: ./mstfaxwsf.py example.com   or   ./mstfaxwsf.py (menu)"""
import sys

if sys.version_info < (3, 8):
    sys.exit("MSTFAXWSF needs Python 3.8 or newer.")

from mstfax.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
