"""XSSentinel identity and banner fingerprint."""

from __future__ import annotations

import hashlib
from pathlib import Path

FINGERPRINT_ID = "rafashacodeid"
AUTHOR_URL = "https://github.com/rafashaalfiandi"
FINGERPRINT_SIGNATURE = "xsentinel-core-runtime-rafashacodeid"
EXPECTED_BANNER_SHA256 = "ac762b9d4f14fc3f195dd4f1289137841e00c599d8462e80c38094fcd1afe776"
EXPECTED_IDENTITY_SHA256 = "deb1c91d3745bd8e7968b6307d31721ca75c187700cf88cef047c6ec8b27882f"
ALLOWED_ENTRYPOINT_NAMES = {"xssentinel", "main.py"}

BANNER = r"""
   _  ____________            __  _            __
  | |/ / ___/ ___/___  ____  / /_(_)___  ___  / /
  |   /\__ \\__ \/ _ \/ __ \/ __/ / __ \/ _ \/ /
 /   |___/ /__/ /  __/ / / / /_/ / / / /  __/ /
/_/|_/____/____/\___/_/ /_/\__/_/_/ /_/\___/_/
"""


def rafashacodeid() -> dict[str, str]:
    return {
        "fingerprint": FINGERPRINT_ID,
        "signature": FINGERPRINT_SIGNATURE,
        "author": AUTHOR_URL,
    }


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def verify_identity(invoked_as: str | None = None) -> None:
    banner_hash = _sha256(BANNER)
    identity_hash = _sha256(f"{FINGERPRINT_ID}|{AUTHOR_URL}|{FINGERPRINT_SIGNATURE}")
    if banner_hash != EXPECTED_BANNER_SHA256:
        raise RuntimeError("banner fingerprint mismatch")
    if identity_hash != EXPECTED_IDENTITY_SHA256:
        raise RuntimeError("identity fingerprint mismatch")
    if invoked_as:
        entrypoint = Path(invoked_as).name
        if entrypoint not in ALLOWED_ENTRYPOINT_NAMES:
            raise RuntimeError(f"entrypoint rename detected: {entrypoint}")
