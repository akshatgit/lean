"""FastAPI + SQLAlchemy adapter (steps 2a and 2b).

Static, deterministic extraction with Python's `ast`. Supported patterns:

  routes      @app.get / @router.get(...) with APIRouter(prefix=...)
  principal   arg = Depends(get_current_user)  (any dependency whose name mentions user/auth)
  params      path params, simple-typed query params, Pydantic body fields (body.x)
  reads       db.get(Model, x); db.query(Model).filter(...).first(); db.execute(select(Model).where(...))
  writes      row.attr = v (update), db.delete(row), Model(...) + db.add (create),
              query(...).filter(...).delete() / .update(...)
  guards      `if COND: raise ...`  ->  guard = not COND (for !=, or, and, not, `is None`)
  helpers     calls the parser cannot see into: a committed summary (step 2b), else Opaque

Anything outside these patterns becomes Opaque, so the endpoint is UNKNOWN, never SAFE.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from .. import air
from ..summaries import instantiate

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
QUERY_PASSTHROUGH = {"first", "one", "one_or_none", "scalar_one_or_none", "scalar_one",
                     "all", "scalars", "scalar", "unique", "limit", "offset", "order_by",
                     "options", "distinct"}
SKIP_DIRS = {".keyhole", ".git", ".venv", "venv", "node_modules", "__pycache__", ".lake"}
TYPE_MAP = {"int": "int", "str": "str", "bool": "bool", "UUID": "uuid", "uuid": "uuid"}


def _dotted(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _python_files(repo: Path):
    for p in sorted(repo.rglob("*.py")):
        if not any(part in SKIP_DIRS for part in p.parts):
            yield p


def find_models(trees) -> set:
    """ORM classes: anything declaring __tablename__ or SQLModel(table=True)."""
    models = set()
    for tree in trees:
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            has_table = any(isinstance(s, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "__tablename__" for t in s.targets)
                for s in node.body)
            sqlmodel = any(kw.arg == "table" for kw in node.keywords)
            if has_table or sqlmodel:
                models.add(node.name)
    return models


class FastAPISQLAlchemyAdapter:
    name = "fastapi+sqlalchemy"

    def detect(self, repo: Path) -> float:
        for p in _python_files(repo):
            if re.search(r"^\s*(from|import)\s+fastapi", p.read_text(errors="ignore"), re.M):
                return 1.0
        return 0.0

    def extract(self, repo: Path, summaries: dict) -> list:
        parsed = []
        for p in _python_files(repo):
            try:
                parsed.append((p, ast.parse(p.read_text(errors="ignore"))))
            except SyntaxError:
                continue
        models = find_models(t for _, t in parsed)
        endpoints = []
        for path, tree in parsed:
            prefixes = self._router_prefixes(tree)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for method, route in self._routes(node, prefixes):
                        rel = str(path.relative_to(repo))
                        fa = _FunctionAnalyzer(node, models, summaries, rel, method, route)
                        endpoints.append(fa.run())
        return endpoints

    @staticmethod
    def _router_prefixes(tree) -> dict:
        out = {}
        for node in ast.walk(tree):
            if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                    and _dotted(node.value.func) in ("APIRouter", "fastapi.APIRouter")):
                prefix = next((kw.value.value for kw in node.value.keywords
                               if kw.arg == "prefix" and isinstance(kw.value, ast.Constant)), "")
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        out[t.id] = prefix
        return out

    @staticmethod
    def _routes(fn, prefixes):
        for dec in fn.decorator_list:
            if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                    and dec.func.attr in HTTP_METHODS and dec.args
                    and isinstance(dec.args[0], ast.Constant)):
                owner = _dotted(dec.func.value) or ""
                yield dec.func.attr.upper(), prefixes.get(owner, "") + dec.args[0].value


class _Unsupported(Exception):
    pass


class _FunctionAnalyzer:
    def __init__(self, fn, models, summaries, file, method, route):
        self.fn, self.models, self.summaries = fn, models, summaries
        self.ep = air.Endpoint(method=method, path=route, file=file, line=fn.lineno)
        self.path_params = set(re.findall(r"{(\w+)}", route))
        self.principal = None
        self.db_vars = {"db", "session"}
        self.body_vars = set()
        self.rows = {}            # var -> {"model", "selector", "guards", "line", "assumed_from"}
        self.creates = {}         # var -> {"model", "fields", "line"}
        self.global_guards = []
        self.updated = set()

    # ---------- entry ----------
    def run(self) -> air.Endpoint:
        self._signature()
        self._block(self.fn.body)
        for var, r in self.rows.items():
            self._emit("read", r["model"], r["selector"], r["guards"], r["line"], r["assumed_from"])
        return self.ep

    # ---------- signature: principal, db, params ----------
    def _signature(self):
        args = self.fn.args.args + self.fn.args.kwonlyargs
        defaults = [None] * (len(self.fn.args.args) - len(self.fn.args.defaults)) + \
            list(self.fn.args.defaults) + list(self.fn.args.kw_defaults)
        for arg, default in zip(args, defaults):
            dep = self._depends_target(default) or self._depends_target(arg.annotation)
            if dep is not None:
                low = dep.lower()
                if any(k in low for k in ("user", "auth", "principal")):
                    self.principal = arg.arg
                    self.ep.principal_binding = arg.arg
                    self.ep.principal_via = "dependency"
                elif any(k in low for k in ("db", "session")):
                    self.db_vars.add(arg.arg)
                continue
            tname = _dotted(arg.annotation) if arg.annotation is not None else None
            short = tname.split(".")[-1] if tname else None
            if arg.arg in self.path_params:
                self.ep.params[arg.arg] = air.Param(arg.arg, "path", TYPE_MAP.get(short, "other"))
            elif short in TYPE_MAP or short is None:
                self.ep.params[arg.arg] = air.Param(arg.arg, "query", TYPE_MAP.get(short, "other"))
            else:
                self.body_vars.add(arg.arg)

    @staticmethod
    def _depends_target(node):
        if node is None:
            return None
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Call) and _dotted(sub.func) in ("Depends", "fastapi.Depends")
                    and sub.args):
                return _dotted(sub.args[0]) or "?"
        return None

    # ---------- terms and predicates ----------
    def term(self, e):
        if isinstance(e, ast.Constant) and e.value is not None:
            return air.const(e.value)
        if isinstance(e, ast.Name) and e.id in self.ep.params:
            return air.param(e.id)
        if isinstance(e, ast.Attribute) and isinstance(e.value, ast.Name):
            base = e.value.id
            if base == self.principal:
                return air.principal(e.attr)
            if base in self.body_vars:
                name = f"{base}.{e.attr}"
                self.ep.params.setdefault(name, air.Param(name, "body", "other"))
                return air.param(name)
            if base in self.models or base in self.rows or base in self.creates:
                return air.fld(e.attr)
        if (isinstance(e, ast.Call) and _dotted(e.func) in ("str", "int", "UUID", "uuid.UUID")
                and len(e.args) == 1):
            return self.term(e.args[0])
        return None

    def cond(self, e):
        """Predicate for a filter/where clause."""
        if isinstance(e, ast.Compare) and len(e.ops) == 1 and isinstance(e.ops[0], ast.Eq):
            a, b = self.term(e.left), self.term(e.comparators[0])
            if a is None or b is None:
                raise _Unsupported("filter term")
            return air.eq(a, b)
        if isinstance(e, ast.BoolOp):
            parts = [self.cond(v) for v in e.values]
            return air.and_(*parts) if isinstance(e.op, ast.And) else air.or_(*parts)
        if isinstance(e, ast.Call) and _dotted(e.func) in ("and_", "sqlalchemy.and_"):
            return air.and_(*[self.cond(a) for a in e.args])
        if isinstance(e, ast.Call) and _dotted(e.func) in ("or_", "sqlalchemy.or_"):
            return air.or_(*[self.cond(a) for a in e.args])
        raise _Unsupported("filter clause")

    def neg(self, e):
        """Predicate that holds when `if e: raise` does NOT raise."""
        if isinstance(e, ast.Compare) and len(e.ops) == 1:
            op, rhs = e.ops[0], e.comparators[0]
            if isinstance(op, ast.NotEq):
                a, b = self.term(e.left), self.term(rhs)
                if a is None or b is None:
                    raise _Unsupported("guard term")
                return air.eq(a, b)
            if isinstance(op, ast.Is) and isinstance(rhs, ast.Constant) and rhs.value is None:
                return True
            raise _Unsupported("guard comparison")
        if isinstance(e, ast.BoolOp):
            parts = [self.neg(v) for v in e.values]
            return air.and_(*parts) if isinstance(e.op, ast.Or) else air.or_(*parts)
        if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
            return self.pos(e.operand)
        if isinstance(e, ast.Attribute):
            t = self.term(e)
            if t is None:
                raise _Unsupported("guard attribute")
            return air.eq(t, air.const("false"))
        raise _Unsupported("guard")

    def pos(self, e):
        """Predicate that holds when `e` is truthy."""
        if isinstance(e, ast.Compare) and len(e.ops) == 1 and isinstance(e.ops[0], ast.Eq):
            return self.cond(e)
        if isinstance(e, ast.BoolOp):
            parts = [self.pos(v) for v in e.values]
            return air.and_(*parts) if isinstance(e.op, ast.And) else air.or_(*parts)
        if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
            return self.neg(e.operand)
        if isinstance(e, ast.Name) and e.id in self.rows:
            return True
        if isinstance(e, ast.Attribute):
            t = self.term(e)
            if t is None:
                raise _Unsupported("guard attribute")
            return air.eq(t, air.const("true"))
        raise _Unsupported("guard")

    # ---------- queries ----------
    def query(self, e):
        """Return (model, selector, terminal) for an ORM query expression, or None."""
        model, conds, terminal = None, [], None
        node = e
        while True:
            if not isinstance(node, ast.Call):
                break
            f = node.func
            if isinstance(f, ast.Name) and f.id == "select" and node.args:
                model = _dotted(node.args[0])
                break
            if not isinstance(f, ast.Attribute):
                return None
            recv = _dotted(f.value)
            if f.attr in ("filter", "where"):
                conds += [self.cond(a) for a in node.args]
            elif f.attr == "filter_by":
                conds += [air.eq(air.fld(kw.arg), self._req(self.term(kw.value))) for kw in node.keywords]
            elif f.attr == "query" and node.args:
                model = _dotted(node.args[0])
                break
            elif f.attr == "get" and recv in self.db_vars and len(node.args) >= 2:
                model = _dotted(node.args[0])
                conds.append(air.eq(air.fld("id"), self._req(self.term(node.args[1]))))
                break
            elif f.attr in ("execute", "scalars", "scalar", "exec") and recv in self.db_vars and node.args:
                node = node.args[0]
                continue
            elif f.attr in ("delete", "update") and recv not in self.db_vars:
                terminal = f.attr
            elif f.attr not in QUERY_PASSTHROUGH:
                return None
            node = f.value
        if model not in self.models:
            return None
        return model, air.and_(*conds), terminal

    @staticmethod
    def _req(t):
        if t is None:
            raise _Unsupported("term")
        return t

    # ---------- statements ----------
    def _block(self, stmts):
        for s in stmts:
            try:
                self._stmt(s)
            except _Unsupported as ex:
                self.ep.opaque.append(air.Opaque(ast.unparse(s)[:120], "unsupported_pattern", s.lineno))

    def _stmt(self, s):
        if isinstance(s, ast.If):
            if any(isinstance(b, ast.Raise) for b in s.body) and not s.orelse:
                self._guard(s.test)
            else:
                self._block(s.body)
                self._block(s.orelse)
            return
        if isinstance(s, (ast.With, ast.AsyncWith, ast.For, ast.AsyncFor, ast.While)):
            self._block(s.body)
            return
        if isinstance(s, ast.Try):
            self._block(s.body)
            return
        if isinstance(s, ast.Assign) and len(s.targets) == 1:
            self._assign(s.targets[0], s.value, s.lineno)
            return
        if isinstance(s, ast.AnnAssign) and s.value is not None:
            self._assign(s.target, s.value, s.lineno)
            return
        if isinstance(s, ast.Expr) and isinstance(s.value, (ast.Call, ast.Await)):
            call = s.value.value if isinstance(s.value, ast.Await) else s.value
            self._call(call, s.lineno)
            return
        if isinstance(s, ast.Return) and s.value is not None:
            self._expr_effects(s.value, s.lineno)

    def _guard(self, test):
        refs = {n.id for n in ast.walk(test) if isinstance(n, ast.Name) and n.id in self.rows}
        g = self.neg(test)
        if refs:
            for v in refs:
                self.rows[v]["guards"].append(g)
        else:
            self.global_guards.append(g)

    def _assign(self, target, value, line):
        if isinstance(value, ast.Await):
            value = value.value
        if isinstance(target, ast.Name):
            q = self.query(value) if isinstance(value, ast.Call) else None
            if q:
                model, sel, terminal = q
                if terminal:
                    self._emit(terminal, model, sel, list(self.global_guards), line)
                else:
                    self.rows[target.id] = {"model": model, "selector": sel,
                                            "guards": list(self.global_guards),
                                            "line": line, "assumed_from": None}
                return
            if isinstance(value, ast.Call) and _dotted(value.func) in self.models:
                fields = [air.eq(air.fld(kw.arg), t) for kw in value.keywords
                          if kw.arg and (t := self.term(kw.value)) is not None]
                self.creates[target.id] = {"model": _dotted(value.func), "fields": fields, "line": line}
                return
            if isinstance(value, ast.Call):
                self._helper(target.id, value, line)
            return
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            var = target.value.id
            if var in self.creates:
                t = self.term(value)
                if t is not None:
                    self.creates[var]["fields"].append(air.eq(air.fld(target.attr), t))
            elif var in self.rows and var not in self.updated:
                r = self.rows[var]
                self.updated.add(var)
                self._emit("update", r["model"], r["selector"], list(r["guards"]), line, r["assumed_from"])

    def _helper(self, var, call, line):
        name = _dotted(call.func)
        uses_input = any(self.term(a) is not None for a in call.args + [k.value for k in call.keywords])
        if name in self.summaries:
            s = self.summaries[name]
            bound = {}
            for i, a in enumerate(call.args):
                if i < len(s.args):
                    bound[s.args[i]] = a
            for kw in call.keywords:
                bound[kw.arg] = kw.value
            sel = instantiate(s.selector, lambda n: self.term(bound[n]) if n in bound else None)
            if sel is None:
                self.ep.opaque.append(air.Opaque(f"{name}(...)", "unsupported_pattern", line))
                return
            label = None if s.reviewed else name
            if s.kind == "read":
                self.rows[var] = {"model": s.resource, "selector": sel,
                                  "guards": list(self.global_guards), "line": line, "assumed_from": label}
            else:
                self._emit(s.kind, s.resource, sel, list(self.global_guards), line, label)
            return
        if uses_input:
            self.ep.opaque.append(air.Opaque(f"{name}(...)", "source_unavailable", line))

    def _call(self, call, line):
        f = call.func
        if isinstance(f, ast.Attribute) and _dotted(f.value) in self.db_vars and call.args:
            arg = call.args[0]
            var = arg.id if isinstance(arg, ast.Name) else None
            if f.attr == "delete" and var in self.rows:
                r = self.rows[var]
                self._emit("delete", r["model"], r["selector"], list(r["guards"]), line, r["assumed_from"])
                return
            if f.attr == "add" and var in self.creates:
                c = self.creates.pop(var)
                self._emit("create", c["model"], air.and_(*c["fields"]), list(self.global_guards), line)
                return
        self._expr_effects(call, line)

    def _expr_effects(self, e, line):
        if isinstance(e, ast.Await):
            e = e.value
        if isinstance(e, ast.Call):
            q = self.query(e)
            if q:
                model, sel, terminal = q
                if terminal:
                    self._emit(terminal, model, sel, list(self.global_guards), line)
                else:
                    self._emit("read", model, sel, list(self.global_guards), line)
            elif _dotted(e.func) not in self.models:
                self._helper("_ret", e, line)

    def _emit(self, kind, model, selector, guards, line, assumed_from=None):
        self.ep.effects.append(air.Effect(kind, model, selector, guards, line, assumed_from))
