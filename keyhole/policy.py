"""Policy file (keyhole.policy.yaml) loading.

Example:

    principal:
      id: current_user.id
      bypass: current_user.is_superuser     # optional: superusers may access everything
    relations:
      member: {table: folder_members, subject: user_id, object: folder_id}
    resources:
      Document:
        confirmed: true                      # a developer reviewed these rules
        read:   owner(owner_id) or visibility == 'public'
        update: owner(owner_id)
        delete: owner(owner_id)
        create: owner(owner_id)

Rule expressions:
    owner(FIELD)            row.FIELD == principal.<id attr>
    member(FIELD)           the caller is in relation `member` with row.FIELD
    member(REL, FIELD)      the caller is in named relation REL with row.FIELD
    FIELD == 'const'        row.FIELD equals a constant
    FIELD == principal.X    row.FIELD equals a principal attribute
    true | false, and, or, parentheses
A missing kind means deny.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import air

_TOKEN = re.compile(r"\s*(\(|\)|,|==|'[^']*'|\"[^\"]*\"|[A-Za-z_][A-Za-z0-9_.]*|\d+)")


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    rules: dict = field(default_factory=dict)        # (resource, kind) -> pred
    confirmed: dict = field(default_factory=dict)    # resource -> bool
    id_attr: str = "id"
    principal_dependencies: set[str] = field(default_factory=set)
    principal_types: set[str] = field(default_factory=set)
    superuser_dependencies: set[str] = field(default_factory=set)
    superuser_types: set[str] = field(default_factory=set)
    helper_guards: dict[str, air.Pred] = field(default_factory=dict)
    ignored_calls: set[str] = field(default_factory=set)
    metadata: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> list:
        return [{"resource": r, "kind": k, "allow": p} for (r, k), p in self.rules.items()]

    def is_confirmed(self, resource: str) -> bool:
        return self.confirmed.get(resource, False)

    def rule(self, resource: str, kind: str):
        return self.rules.get((resource, kind), False)


class _Parser:
    def __init__(self, text: str, id_attr: str):
        self.toks = _tokenize(text)
        self.i = 0
        self.id_attr = id_attr

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self, expected=None):
        tok = self.peek()
        if tok is None or (expected and tok != expected):
            raise PolicyError(f"expected {expected or 'token'}, got {tok!r}")
        self.i += 1
        return tok

    def parse(self):
        p = self.disj()
        if self.peek() is not None:
            raise PolicyError(f"unexpected {self.peek()!r}")
        return p

    def disj(self):
        parts = [self.conj()]
        while self.peek() == "or":
            self.take()
            parts.append(self.conj())
        return air.or_(*parts)

    def conj(self):
        parts = [self.atom()]
        while self.peek() == "and":
            self.take()
            parts.append(self.atom())
        return air.and_(*parts)

    def atom(self):
        tok = self.take()
        if tok == "(":
            p = self.disj()
            self.take(")")
            return p
        if tok == "true":
            return True
        if tok == "false":
            return False
        if tok in ("owner", "member", "is_null") and self.peek() == "(":
            self.take("(")
            f = self.take()
            relation = "member"
            if tok == "member" and self.peek() == ",":
                self.take(",")
                relation, f = f, self.take()
                if not all(name.isidentifier() for name in (relation, f)):
                    raise PolicyError("member expects a relation name and a field name")
            self.take(")")
            if tok == "is_null":
                return air.eq(air.fld(f), air.const(None))
            if tok == "owner":
                return air.eq(air.fld(f), air.principal(self.id_attr))
            return air.member(relation, air.principal(self.id_attr), air.fld(f))
        lhs = self.term(tok, side="lhs")
        self.take("==")
        rhs = self.term(self.take(), side="rhs")
        return air.eq(lhs, rhs)

    def term(self, tok: str, side: str):
        if tok[0] in "'\"":
            return air.const(tok[1:-1])
        if tok.isdigit():
            return air.const(tok)
        if tok.startswith("principal."):
            return air.principal(tok.split(".", 1)[1])
        return air.fld(tok)


def _tokenize(text: str) -> list:
    out, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise PolicyError(f"cannot parse policy near: {text[pos:]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


def parse_rule(text, id_attr: str = "id"):
    if isinstance(text, bool):
        return text
    return _Parser(str(text), id_attr).parse()


def load_policy(path: str | Path) -> Policy:
    data = yaml.safe_load(Path(path).read_text()) or {}
    pr = data.get("principal", {}) or {}
    id_attr = str(pr.get("id", "current_user.id")).split(".")[-1]
    bypass = pr.get("bypass")
    bypass_pred = air.eq(air.principal(str(bypass).split(".")[-1]), air.const("true")) if bypass else None
    pol = Policy(
        id_attr=id_attr,
        principal_dependencies={str(x) for x in (pr.get("dependencies") or [])},
        principal_types={str(x) for x in (pr.get("types") or [])},
        superuser_dependencies={str(x) for x in (pr.get("superuser_dependencies") or [])},
        superuser_types={str(x) for x in (pr.get("superuser_types") or [])},
        metadata={
            key: str(data[key])
            for key in ("generated_by", "status", "generated_at", "source_revision")
            if data.get(key) is not None
        },
    )
    for name, rule in (data.get("helpers") or {}).items():
        pol.helper_guards[str(name)] = parse_rule(rule, id_attr)
    adapter_config = data.get("adapter") or {}
    pol.ignored_calls = {str(x) for x in (adapter_config.get("ignore_calls") or [])}
    for res, rules in (data.get("resources") or {}).items():
        pol.confirmed[res] = bool(rules.get("confirmed", False))
        for kind in air.KINDS:
            if kind not in rules:
                continue
            pred = parse_rule(rules[kind], id_attr)
            if bypass_pred is not None:
                pred = air.or_(pred, bypass_pred)
            pol.rules[(res, kind)] = pred
    return pol
