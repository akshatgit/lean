"""Authorization Intermediate Representation (AIR): Python side.

Terms and predicates are plain JSON-compatible dicts, in exactly the shape the
Lean core (core/Main.lean) parses:

    TERM := {"param": NAME} | {"principal": ATTR} | {"field": NAME} | {"const": VALUE}
    PRED := True | False | {"eq": [TERM, TERM]} | {"member": [REL, TERM, TERM]}
          | {"and": [PRED, ...]} | {"or": [PRED, ...]}
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

AIR_VERSION = 1

Term = dict
Pred = Any  # bool | dict

KINDS = ("read", "update", "delete", "create")
PARAM_SOURCES = ("path", "query", "body", "header", "cookie")
PARAM_TYPES = ("uuid", "int", "str", "bool", "other")
PRINCIPAL_VIA = ("dependency", "middleware", "external", "none")
OPAQUE_REASONS = ("source_unavailable", "dynamic_call", "unsupported_pattern", "raw_sql")


def param(name: str) -> Term:
    return {"param": name}


def principal(attr: str) -> Term:
    return {"principal": attr}


def fld(name: str) -> Term:
    return {"field": name}


def const(value: Any) -> Term:
    if isinstance(value, bool):
        value = "true" if value else "false"
    return {"const": str(value)}


def eq(a: Term, b: Term) -> Pred:
    return {"eq": [a, b]}


def member(rel: str, subj: Term, obj: Term) -> Pred:
    return {"member": [rel, subj, obj]}


def and_(*ps: Pred) -> Pred:
    ps = [p for p in ps if p is not True]
    if any(p is False for p in ps):
        return False
    if not ps:
        return True
    return ps[0] if len(ps) == 1 else {"and": list(ps)}


def or_(*ps: Pred) -> Pred:
    ps = [p for p in ps if p is not False]
    if any(p is True for p in ps):
        return True
    if not ps:
        return False
    return ps[0] if len(ps) == 1 else {"or": list(ps)}


def show_term(t: Term) -> str:
    (k, v), = t.items()
    if k == "param":
        return f"param.{v}"
    if k == "principal":
        return f"principal.{v}"
    if k == "field":
        return f"row.{v}"
    return repr(v)


def show_pred(p: Pred) -> str:
    if p is True or p is False:
        return str(p).lower()
    (k, v), = p.items()
    if k == "eq":
        return f"{show_term(v[0])} == {show_term(v[1])}"
    if k == "member":
        return f"{v[0]}({show_term(v[1])}, {show_term(v[2])})"
    joiner = " and " if k == "and" else " or "
    return "(" + joiner.join(show_pred(x) for x in v) + ")"


@dataclass
class Param:
    name: str
    source: str = "path"
    type: str = "str"
    attacker_controlled: bool = True

    def to_json(self) -> dict:
        return {"from": self.source, "type": self.type,
                "attacker_controlled": self.attacker_controlled}


@dataclass
class Effect:
    kind: str
    resource: str
    selector: Pred
    guards: list = field(default_factory=list)
    line: int = 0
    assumed_from: str | None = None   # summary name if this effect came from an LLM summary

    def to_json(self) -> dict:
        d = {"kind": self.kind, "resource": self.resource,
             "selector": self.selector, "guards": self.guards, "line": self.line}
        if self.assumed_from:
            d["assumed_from"] = self.assumed_from
        return d


@dataclass
class Opaque:
    call: str
    reason: str
    line: int = 0
    # Opacity has two independent consequences for a verdict:
    #   may_block        - an unmodeled guard/denial might exist here, so a Lean
    #                      counterexample that passes this point is only a lead
    #                      (blocks VIOLATION).
    #   may_have_effects - an unmodeled read/write might exist here, so the modeled
    #                      effects may be incomplete (blocks SAFE / no_effects).
    may_block: bool = True
    may_have_effects: bool = True

    def to_json(self) -> dict:
        return {"call": self.call, "reason": self.reason, "line": self.line,
                "may_block": self.may_block, "may_have_effects": self.may_have_effects}


@dataclass
class UnmodeledCheck:
    expression: str
    line: int = 0

    def to_json(self) -> dict:
        return {"expression": self.expression, "line": self.line}


@dataclass
class Endpoint:
    method: str
    path: str
    file: str
    line: int
    principal_binding: str | None = None
    principal_via: str = "none"
    params: dict = field(default_factory=dict)
    effects: list = field(default_factory=list)
    opaque: list = field(default_factory=list)
    unmodeled_checks: list = field(default_factory=list)
    # Assumption provenance: id -> human-readable reason for EVERY unproven claim this
    # endpoint's model rests on (a suppressed call, a declared guard, an unreviewed
    # summary, an identity fact, ...).  It is a set and only ever grows; a verdict may be
    # clean green only if it is empty.
    assumptions: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"

    def to_json(self) -> dict:
        return {
            "air_version": AIR_VERSION,
            "endpoint": self.key,
            "source": f"{self.file}:{self.line}",
            "principal": {"binding": self.principal_binding, "via": self.principal_via},
            "params": {k: p.to_json() for k, p in self.params.items()},
            "effects": [e.to_json() for e in self.effects],
            "opaque": [o.to_json() for o in self.opaque],
            "unmodeled_checks": [c.to_json() for c in self.unmodeled_checks],
            "assumptions": [{"id": key, "reason": self.assumptions[key]}
                            for key in sorted(self.assumptions)],
        }
