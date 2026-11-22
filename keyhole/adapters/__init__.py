"""Adapter registry. Built-in adapters plus any registered under the
`keyhole.adapters` entry-point group."""
from __future__ import annotations

from importlib.metadata import entry_points

from .fastapi_sqla import FastAPISQLAlchemyAdapter

BUILTIN = [FastAPISQLAlchemyAdapter]


def all_adapters():
    found = [cls() for cls in BUILTIN]
    for ep in entry_points(group="keyhole.adapters"):
        found.append(ep.load()())
    return found


def pick(repo, name: str | None = None):
    adapters = all_adapters()
    if name:
        for a in adapters:
            if a.name == name:
                return a
        raise SystemExit(f"unknown adapter {name!r}; have: {[a.name for a in adapters]}")
    best = max(adapters, key=lambda a: a.detect(repo))
    if best.detect(repo) <= 0:
        raise SystemExit("no adapter recognizes this repo")
    return best
