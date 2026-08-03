#!/usr/bin/env python3
"""XSSentinel command-line entrypoint."""

from __future__ import annotations

from pathlib import Path
import sys


BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from xssentinel_core.scanner.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
