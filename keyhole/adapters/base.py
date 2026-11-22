"""Adapter plugin interface.

An adapter turns source code into AIR endpoints. Third-party adapters register
through the `keyhole.adapters` entry-point group and implement this protocol.
Rule for every adapter: emit Opaque instead of guessing.
"""
from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..air import Endpoint


class Adapter(Protocol):
    name: str

    def detect(self, repo: Path) -> float:
        """Confidence 0-1 that this adapter applies to the repo."""

    def extract(self, repo: Path, summaries: dict, *, include_tests: bool = False,
                policy=None) -> list[Endpoint]:
        """Return one AIR endpoint per route found."""
