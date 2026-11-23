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
import copy
import re
from dataclasses import dataclass, field
from pathlib import Path

from .. import air
from .purity import Purity
from ..summaries import instantiate

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
QUERY_PASSTHROUGH = {"first", "one", "one_or_none", "scalar_one_or_none", "scalar_one",
                     "all", "scalars", "scalar", "unique", "limit", "offset", "order_by",
                     "options", "distinct"}
# site-packages/dist-packages: an environment checked out inside the repository is
# third-party code, not the application.  Treating it as "repository source" would let
# the adapter resolve application calls into unrelated installed packages.
SKIP_DIRS = {".keyhole", ".git", ".venv", "venv", "node_modules", "__pycache__", ".lake",
             "site-packages", "dist-packages"}
TEST_FILES = {"conftest.py"}
TYPE_MAP = {"int": "int", "str": "str", "bool": "bool", "UUID": "uuid", "uuid": "uuid"}
IGNORED_CALLS = {
    "str", "int", "bool", "len", "max", "min", "getattr", "setattr", "hasattr",
    "isinstance", "dict", "list", "set", "tuple", "frozenset", "sorted", "any", "all",
    "next", "callable", "print", "super", "UUID", "Path", "BytesIO", "StringIO", "col",
    "Response", "JSONResponse", "StreamingResponse", "HTMLResponse", "RedirectResponse",
    "FileResponse", "PlainTextResponse", "HTTPException",
}
IGNORED_METHODS = {
    "model_validate", "model_dump", "model_dump_json", "dict", "json",
    "commit", "flush", "refresh", "rollback", "close",
}
CONTAINER_METHODS = {
    "get", "append", "extend", "add", "update", "pop", "setdefault", "items", "keys", "values",
}
CONTAINER_TYPES = {"dict", "list", "set", "tuple", "Mapping", "MutableMapping", "Sequence"}
LOG_METHODS = {
    "debug", "info", "warning", "error", "exception", "critical", "adebug", "ainfo", "awarning",
    "aerror", "aexception", "log",
}
KNOWN_NON_DB_CALLS = {
    "asyncio.Queue", "asyncio.get_running_loop", "asyncio.create_task",
    "time.monotonic", "time.time", "datetime.datetime.now", "datetime.now",
    "json.loads", "json.dumps", "os.getenv", "os.environ.get",
}
KNOWN_NON_DB_TYPED_METHODS = {
    "asyncio.AbstractEventLoop": {"is_closed", "create_task", "create_future"},
    "asyncio.Task": {"done", "cancelled", "exception", "cancel"},
    "asyncio.Queue": {"put", "put_nowait", "get", "get_nowait", "qsize", "task_done", "empty"},
}


def _dotted(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _annotation_dotted(node) -> str | None:
    if isinstance(node, ast.Subscript):
        return _dotted(node.value)
    direct = _dotted(node)
    if direct:
        return direct
    if node is not None:
        for sub in ast.walk(node):
            direct = _dotted(sub)
            if direct and direct not in {"None", "typing"}:
                return direct
    return None


def _python_files(repo: Path, include_tests: bool = False):
    for p in sorted(repo.rglob("*.py")):
        if not any(part in SKIP_DIRS for part in p.parts):
            if not include_tests:
                rel = p.relative_to(repo)
                if "tests" in rel.parts or p.name in TEST_FILES or p.name.startswith("test_") or p.name.endswith("_test.py"):
                    continue
            yield p


def _module_name(repo: Path, path: Path) -> str:
    parts = [] if path.name == "__init__.py" else [path.stem]
    parent = path.parent
    while (parent / "__init__.py").exists():
        parts.insert(0, parent.name)
        parent = parent.parent
    if parts:
        return ".".join(parts)
    return ".".join(path.relative_to(repo).with_suffix("").parts)


@dataclass
class _FunctionRef:
    module: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    file: str
    owner_class: str | None = None


class _RepoIndex:
    """Cross-file aliases, imports, and functions used by the adapter."""

    def __init__(self, repo: Path, parsed: list[tuple[Path, ast.AST]], models: set[str], policy=None):
        self.repo = repo
        self.models = models
        self.modules: dict[str, tuple[Path, ast.AST]] = {}
        self.imports: dict[str, dict[str, str]] = {}
        self.aliases: dict[str, ast.AST] = {}
        self.functions: dict[str, _FunctionRef] = {}
        self.methods_by_name: dict[str, list[_FunctionRef]] = {}
        self.classes: set[str] = set()
        self.summary_cache: dict[tuple, object] = {}
        self.relevance_cache: dict[str, bool] = {}
        self.global_types: dict[tuple[str, str], str] = {}
        self.policy = policy
        self.router_auth: set[str] = set()
        for path, tree in parsed:
            module = _module_name(repo, path)
            self.modules[module] = (path, tree)
            self.imports[module] = self._imports(module, path, tree)
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.functions[f"{module}.{node.name}"] = _FunctionRef(
                        module, node, str(path.relative_to(repo))
                    )
                elif isinstance(node, ast.ClassDef):
                    self.classes.add(node.name)
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            ref = _FunctionRef(module, item, str(path.relative_to(repo)), node.name)
                            self.functions[f"{module}.{node.name}.{item.name}"] = ref
                            self.methods_by_name.setdefault(item.name, []).append(ref)
                elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                    value = node.value
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name) and value is not None:
                            self.aliases[f"{module}.{target.id}"] = value
                    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                        dotted = _annotation_dotted(node.annotation)
                        if dotted:
                            self.global_types[(module, node.target.id)] = dotted
        self._index_router_auth(parsed)
        # Effect-freedom oracle (see purity.py): the only authority allowed to say a
        # call cannot touch the database.
        self.purity = Purity(self, models, policy)

    @staticmethod
    def dependency_names(node) -> set[str]:
        names = set()
        if node is None:
            return names
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Call)
                    and (_dotted(sub.func) or "").split(".")[-1] in {"Depends", "Security"}
                    and sub.args):
                name = _dotted(sub.args[0])
                if name:
                    names.add(name.split(".")[-1])
        return names

    def is_principal_dependency(self, name: str) -> bool:
        return (
            bool(self.policy and name in self.policy.principal_dependencies)
            or any(token in name.lower() for token in ("user", "auth", "principal"))
        )

    def has_principal_dependency(self, node) -> bool:
        return any(self.is_principal_dependency(name) for name in self.dependency_names(node))

    def _index_router_auth(self, parsed):
        includes = []
        for path, tree in parsed:
            module = _module_name(self.repo, path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    kind = (_dotted(node.value.func) or "").split(".")[-1]
                    if kind not in {"APIRouter", "FastAPI"}:
                        continue
                    authenticated = any(
                        kw.arg == "dependencies" and self.has_principal_dependency(kw.value)
                        for kw in node.value.keywords
                    )
                    if authenticated:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                self.router_auth.add(f"{module}.{target.id}")
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "include_router" and node.args):
                    owner = _dotted(node.func.value)
                    child = _dotted(node.args[0])
                    if not owner or not child:
                        continue
                    explicit = any(
                        kw.arg == "dependencies" and self.has_principal_dependency(kw.value)
                        for kw in node.keywords
                    )
                    includes.append((
                        self.resolve_name(module, owner), self.resolve_name(module, child), explicit,
                    ))
        changed = True
        while changed:
            changed = False
            for parent, child, explicit in includes:
                if (explicit or parent in self.router_auth) and child not in self.router_auth:
                    self.router_auth.add(child)
                    changed = True

    def route_has_router_auth(self, module: str, owner: str, decorator: ast.Call) -> bool:
        if self.resolve_name(module, owner) in self.router_auth:
            return True
        return any(
            kw.arg == "dependencies" and self.has_principal_dependency(kw.value)
            for kw in decorator.keywords
        )

    @staticmethod
    def _imports(module: str, path: Path, tree: ast.AST) -> dict[str, str]:
        out = {}
        package = module if path.name == "__init__.py" else module.rpartition(".")[0]
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    out[alias.asname or alias.name.split(".")[0]] = alias.name
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base = package.split(".") if package else []
                    trim = max(0, node.level - 1)
                    if trim:
                        base = base[:-trim]
                    prefix = ".".join([*base, *([node.module] if node.module else [])])
                else:
                    prefix = node.module or ""
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    out[alias.asname or alias.name] = ".".join(x for x in (prefix, alias.name) if x)
        return out

    def resolve_name(self, module: str, name: str, seen: set[tuple[str, str]] | None = None) -> str:
        seen = seen or set()
        key = (module, name)
        if key in seen:
            return name
        seen.add(key)
        first, dot, rest = name.partition(".")
        imported = self.imports.get(module, {}).get(first)
        if imported:
            target = imported + (dot + rest if dot else "")
        else:
            target = f"{module}.{name}" if module else name
        # Follow package re-exports such as `from .core import CurrentActiveUser`.
        parent, _, leaf = target.rpartition(".")
        reexport = self.imports.get(parent, {}).get(leaf)
        if reexport and reexport != target:
            return self.resolve_qualified(reexport, seen)
        return target

    def resolve_qualified(self, qualified: str, seen=None) -> str:
        parent, _, leaf = qualified.rpartition(".")
        if not parent:
            return qualified
        return self.resolve_name(parent, leaf, seen)

    def annotation_dependency(self, module: str, node: ast.AST | None, seen=None) -> str | None:
        if node is None:
            return None
        seen = seen or set()
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Call)
                    and (_dotted(sub.func) or "").split(".")[-1] in {"Depends", "Security"}
                    and sub.args):
                return (_dotted(sub.args[0]) or "?").split(".")[-1]
        for sub in ast.walk(node):
            dotted = _dotted(sub)
            if not dotted:
                continue
            qualified = self.resolve_name(module, dotted)
            if qualified in seen:
                continue
            alias = self.aliases.get(qualified)
            if alias is not None:
                dep = self.annotation_dependency(module=qualified.rpartition(".")[0], node=alias,
                                                 seen=seen | {qualified})
                if dep:
                    return dep
        return None

    def annotation_dependency_module(self, module: str, node: ast.AST | None, seen=None) -> str | None:
        """Module in which the `Depends(f)` target of an `Annotated[...]` alias is named.
        The alias may live in another module than the endpoint that uses it, and `f`
        must be resolved against the alias's imports, not the endpoint's."""
        if node is None:
            return None
        seen = seen or set()
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Call)
                    and (_dotted(sub.func) or "").split(".")[-1] in {"Depends", "Security"}
                    and sub.args):
                return module
        for sub in ast.walk(node):
            dotted = _dotted(sub)
            if not dotted:
                continue
            qualified = self.resolve_name(module, dotted)
            if qualified in seen:
                continue
            alias = self.aliases.get(qualified)
            if alias is not None:
                found = self.annotation_dependency_module(
                    qualified.rpartition(".")[0], alias, seen | {qualified})
                if found:
                    return found
        return None

    def annotation_type(self, module: str, node: ast.AST | None, seen=None) -> str | None:
        if node is None:
            return None
        seen = seen or set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self.classes:
                return sub.id
            dotted = _dotted(sub)
            if not dotted:
                continue
            qualified = self.resolve_name(module, dotted)
            if qualified in seen:
                continue
            alias = self.aliases.get(qualified)
            if alias is not None:
                found = self.annotation_type(
                    qualified.rpartition(".")[0], alias, seen | {qualified}
                )
                if found:
                    return found
        return None

    def resolve_function(self, module: str, dotted: str | None, var_types=None,
                         owner_class: str | None = None) -> _FunctionRef | None:
        if not dotted:
            return None
        qualified = self.resolve_name(module, dotted)
        direct = self.functions.get(qualified)
        if direct is not None:
            return direct
        base, dot, method = dotted.rpartition(".")
        if not dot:
            return None
        if base == "self" and owner_class:
            direct = self.functions.get(f"{module}.{owner_class}.{method}")
            if direct is not None:
                return direct
        type_name = (var_types or {}).get(base)
        if type_name:
            matches = [ref for ref in self.methods_by_name.get(method, []) if ref.owner_class == type_name]
            if len(matches) == 1:
                return matches[0]
        matches = self.methods_by_name.get(method, [])
        return matches[0] if len(matches) == 1 else None

    def function_may_touch_db(self, ref: _FunctionRef, seen=None) -> bool:
        qualified = ".".join(x for x in (ref.module, ref.owner_class, ref.node.name) if x)
        if qualified in self.relevance_cache:
            return self.relevance_cache[qualified]
        seen = set(seen or ())
        if qualified in seen:
            return False
        seen.add(qualified)
        args = [*ref.node.args.posonlyargs, *ref.node.args.args, *ref.node.args.kwonlyargs]
        db_names = {
            arg.arg for arg in args
            if arg.arg in {"db", "session"}
            or "session" in ((_dotted(arg.annotation) or "").lower())
        }
        for call in (node for node in ast.walk(ref.node) if isinstance(node, ast.Call)):
            name = _dotted(call.func) or ""
            short = name.split(".")[-1]
            receiver = name.split(".", 1)[0]
            if short in {"select", "delete", "update"} and any(
                (_dotted(arg) or "").split(".", 1)[0] in self.models for arg in call.args
            ):
                self.relevance_cache[qualified] = True
                return True
            if (receiver in db_names or receiver.split(".")[-1] in {"db", "session"}) and short in {
                "get", "exec", "execute", "scalars", "scalar", "add", "add_all", "delete"
            }:
                self.relevance_cache[qualified] = True
                return True
            child = self.resolve_function(ref.module, name, owner_class=ref.owner_class)
            if child is not None and self.function_may_touch_db(child, seen):
                self.relevance_cache[qualified] = True
                return True
            call_names = {n.id for n in ast.walk(call) if isinstance(n, ast.Name)}
            if call_names & db_names:
                self.relevance_cache[qualified] = True
                return True
        self.relevance_cache[qualified] = False
        return False


class _FieldTerm(dict):
    """An AIR `{"field": name}` term that remembers which local row variable it was read
    from.  AIR itself has a single implicit row per effect, so a field term is only
    meaningful for the effect on THAT row.  `row` is:
        a variable name - the field was read off that tracked row (`doc.owner_id`)
        None            - a column of the query being built (`Doc.owner_id` in a filter)
        "?"             - a field with no row we can name (must never constrain a row)
    Serialises and compares like the plain dict; two provenance-carrying terms are equal
    only if they name the same row."""

    def __init__(self, name: str, row: str | None = None):
        super().__init__(field=name)
        self.row = row

    def __eq__(self, other):
        if not dict.__eq__(self, other):
            return False
        return not isinstance(other, _FieldTerm) or other.row == self.row

    def __ne__(self, other):
        return not self.__eq__(other)

    __hash__ = None

    def __deepcopy__(self, memo):
        return _FieldTerm(self["field"], self.row)


def _field_rows(pred) -> set:
    """Provenance of every field term inside a predicate ("?" when unknown)."""
    out = set()
    todo = [pred]
    while todo:
        node = todo.pop()
        if isinstance(node, dict):
            if "field" in node:
                row = getattr(node, "row", "?")
                out.add("?" if row is None else row)
            else:
                todo.extend(node.values())
        elif isinstance(node, (list, tuple)):
            todo.extend(node)
    return out


@dataclass
class _QueryState:
    model: str
    conds: list = field(default_factory=list)
    terminal: str | None = None
    executed: bool = False
    effect_emitted: bool = False


@dataclass
class _HelperAnalysis:
    effects: list
    opaque: list
    unmodeled_checks: list
    returned_row: dict | None
    row_guards: dict[str, list] = field(default_factory=dict)
    assumptions: dict = field(default_factory=dict)


@dataclass
class _AnalysisState:
    global_guards: list
    rows: dict
    creates: dict
    queries: dict
    query_results: dict
    values: dict
    var_types: dict
    updated: set
    unresolved_values: dict
    global_assumed_from: str | None = None


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

    def extract(self, repo: Path, summaries: dict, *, include_tests: bool = False, policy=None) -> list:
        parsed = []
        for p in _python_files(repo, include_tests=include_tests):
            try:
                parsed.append((p, ast.parse(p.read_text(errors="ignore"))))
            except SyntaxError:
                continue
        models = find_models(t for _, t in parsed)
        index = _RepoIndex(repo, parsed, models, policy)
        endpoints = []
        for path, tree in parsed:
            module = _module_name(repo, path)
            prefixes = self._router_prefixes(tree)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for method, route, router_auth in self._routes(node, prefixes, index, module):
                        rel = str(path.relative_to(repo))
                        fa = _FunctionAnalyzer(
                            node, models, summaries, rel, method, route,
                            index=index, module=module, policy=policy,
                        )
                        endpoint = fa.run()
                        if router_auth and endpoint.principal_via == "none":
                            endpoint.principal_via = "router"
                        endpoints.append(endpoint)
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
    def _routes(fn, prefixes, index, module):
        for dec in fn.decorator_list:
            if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                    and dec.args and isinstance(dec.args[0], ast.Constant)
                    and isinstance(dec.args[0].value, str)):
                continue
            attr = dec.func.attr
            if attr not in HTTP_METHODS and attr not in ("websocket", "api_route"):
                continue
            owner = _dotted(dec.func.value) or ""
            path = prefixes.get(owner, "") + dec.args[0].value
            auth = index.route_has_router_auth(module, owner, dec)
            if attr in HTTP_METHODS:
                yield attr.upper(), path, auth
            elif attr == "websocket":
                yield "WEBSOCKET", path, auth
            elif attr == "api_route":
                methods = []
                for kw in dec.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        methods = [m.value.upper() for m in kw.value.elts
                                   if isinstance(m, ast.Constant) and isinstance(m.value, str)]
                for method in (methods or ["GET"]):
                    yield method, path, auth


class _Unsupported(Exception):
    pass


class _FunctionAnalyzer:
    def __init__(self, fn, models, summaries, file, method, route, *, index=None,
                 module="", policy=None, depth=0, call_stack=None, helper_mode=False,
                 analyze_dependencies=True):
        self.fn, self.models, self.summaries = fn, models, summaries
        self.ep = air.Endpoint(method=method, path=route, file=file, line=fn.lineno)
        self.index = index
        self.module = module
        self.policy = policy
        self.depth = depth
        self.call_stack = set(call_stack or ())
        self.helper_mode = helper_mode
        # FastAPI injects Depends(...) parameters for routes and for dependencies that are
        # themselves injected. A helper called with explicit arguments does NOT get them
        # injected, so its Depends parameters must not be re-analyzed (that would transfer
        # the dependency's guard onto a row the caller passed in -> false SAFE).
        self.analyze_dependencies = analyze_dependencies
        self.owner_class = None
        self.path_params = set(re.findall(r"{(\w+)}", route))
        self.principal = None
        self.db_vars = {"db", "session"}
        self.body_vars = set()
        self.var_types: dict[str, str] = {}
        self.values: dict[str, air.Term] = {}
        self.rows = {}            # var -> {"model", "selector", "guards", "line", "assumed_from"}
        self.creates = {}         # var -> {"model", "fields", "line"}
        self.queries: dict[str, _QueryState] = {}
        self.query_results: dict[str, _QueryState] = {}
        self.global_guards = []
        self.global_assumed_from = None
        self.updated = set()
        self.unresolved_values: dict[str, tuple[str, int]] = {}
        self.conditional_depth = 0
        self.returned_row = None
        self.returned_rows: list[dict | None] = []
        self.dependency_params: list[tuple[str, str, str]] = []  # (param, dependency, module)
        self.unverified_principals: list[tuple[str, str, str]] = []  # name-matched principals
        # Effects that exist only because a principal dependency fetched the caller.
        self._principal_effect_ids: set[int] = set()
        self.return_states: list[_AnalysisState] = []
        self._try_throw_collectors: list[list[_AnalysisState]] = []
        self._next_effect_id = 0
        # Totality ledger: ids of ast.Call / store-target nodes that were positively
        # modeled.  Every other call in the body is classified by the final sweep.
        self._visited: set[int] = set()
        # Names that ever held an UNEXECUTED query object; handing one to an otherwise
        # trusted first-order callable (or iterating it) may execute it.
        self._query_names: set[str] = set()
        # Names rebound from a nested function (nonlocal/global): never trackable.
        self._untrackable: set[str] = {
            name
            for stmt in fn.body for outer in ast.walk(stmt)
            if isinstance(outer, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
            for inner in ast.walk(outer)
            if isinstance(inner, (ast.Nonlocal, ast.Global))
            for name in inner.names
        }

    # ---------- entry ----------
    def run(self) -> air.Endpoint:
        self._signature()
        self._analyze_body()
        return self.ep

    def _analyze_body(self):
        if self.analyze_dependencies:
            for var, dep_name, dep_module in self.unverified_principals:
                self._analyze_dependency(var, dep_name, dep_module, as_principal=True)
            for var, dep_name, dep_module in self.dependency_params:
                self._analyze_dependency(var, dep_name, dep_module)
            if not self.helper_mode:
                self._endpoint_decorators()
                # `@router.get(..., dependencies=[Depends(f)])` runs f before the body.
                for i, dep_name in enumerate(self._route_dependencies()):
                    short = dep_name.split(".")[-1]
                    if self.policy and (short in self.policy.principal_dependencies
                                        or short in self.policy.superuser_dependencies):
                        continue  # declared in the policy: trusted authentication
                    # A name that merely looks like authentication is verified like a
                    # name-matched principal parameter; anything else is a dependency.
                    looks_like_auth = bool(self.index and self.index.is_principal_dependency(short))
                    self._analyze_dependency(f"<route dependency {i}>", dep_name,
                                             as_principal=looks_like_auth)
        falls_through = self._block(self.fn.body)
        terminal_states = list(self.return_states)
        if falls_through:
            terminal_states.append(self._snapshot())
        if terminal_states:
            self._restore(self._merge_states(terminal_states))
        self._totality_sweep()
        self._finalize_returned_row()
        for var, r in self.rows.items():
            if not r.get("read_emitted"):
                effect = self._emit(
                    "read", r["model"], r["selector"], r["guards"], r["line"], r["assumed_from"]
                )
                r["effect_id"] = getattr(effect, "_analysis_id", None)
                r["read_emitted"] = True
        self._sync_row_effects()

    def _endpoint_decorators(self):
        """A decorator other than the route registration wraps the handler in code that
        runs on every request and that we do not read."""
        purity = self.index.purity if self.index else None
        for dec in self.fn.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            is_route = (isinstance(dec, ast.Call) and isinstance(target, ast.Attribute)
                        and target.attr in HTTP_METHODS | {"websocket", "api_route"})
            if is_route:
                continue
            probe = ast.FunctionDef(name=self.fn.name, args=self.fn.args, body=[],
                                    decorator_list=[dec], lineno=self.fn.lineno, col_offset=0)
            if purity is not None and purity._decorators_ok(self.module, probe, self.owner_class):
                continue
            self._opaque(f"@{ast.unparse(target)[:80]}", "endpoint_decorator", self.fn.lineno)

    def _route_dependencies(self) -> list[str]:
        out = []
        for dec in self.fn.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            for kw in dec.keywords:
                if kw.arg != "dependencies":
                    continue
                for sub in ast.walk(kw.value):
                    if (isinstance(sub, ast.Call)
                            and (_dotted(sub.func) or "").split(".")[-1] in ("Depends", "Security")):
                        out.append((_dotted(sub.args[0]) if sub.args else None) or "?")
        return out

    # ---------- totality: nothing in the body may be silently skipped ----------
    def _pctx(self):
        return self.index.purity.ctx_for(self.module, self.fn, self.owner_class)

    def _dangerous_names(self) -> frozenset:
        """Names a declared-irrelevant call must not be handed: anything through which
        it could reach the database (handles, live queries, tracked/created rows)."""
        return frozenset(self.db_vars | set(self.rows) | set(self.creates)
                         | set(self.queries) | set(self.query_results))

    def _declaration(self, call):
        """(key, refusal) for the policy ignore_calls entry naming `call` (see
        Purity.declaration_for); (None, None) when there is no index or no entry."""
        if self.index is None or not (self.policy and self.policy.ignored_calls):
            return None, None
        return self.index.purity.declaration_for(self._pctx(), call, self._dangerous_names())

    def _free(self, call) -> bool:
        """True only if the purity oracle PROVES `call` cannot touch the database."""
        if self.index is None:
            return False
        ok, deps = self.index.purity.call_free_deps(
            self._pctx(), call, frozenset(self._query_names), self._dangerous_names())
        self._assume_declared(deps)
        return ok

    def _assume(self, key: str, reason: str):
        """Record that this endpoint's model rests on an unproven claim.  The set only
        grows: nothing downstream may clear or overwrite an entry."""
        self.ep.assumptions.setdefault(key, reason)

    def _assume_declared(self, deps):
        for key in deps:
            name = key.split(":", 1)[1]
            self._assume(key, f"call {name} is declared data-irrelevant in the policy "
                              f"(adapter.ignore_calls); a call was treated as effect-free on that basis")

    def _opaque(self, call: str, reason: str, line: int, *, effects: bool = True, block: bool = True):
        if not any(o.call == call and o.reason == reason and o.line == line for o in self.ep.opaque):
            self.ep.opaque.append(air.Opaque(call, reason, line, block, effects))

    def _kill(self, name: str):
        """Forget everything tracked about a local that was rebound to something unknown."""
        for table in (self.rows, self.creates, self.queries, self.query_results, self.values,
                      self.var_types):
            table.pop(name, None)
        self.updated.discard(name)
        self._forget_fields_of(name)

    def _forget_fields_of(self, row_var: str):
        """`owner = doc.owner_id` is a field of the row `doc` held at that time.  Once
        `doc` names another row the alias must not be read as a field of the new one."""
        for alias in [n for n, t in self.values.items() if getattr(t, "row", None) == row_var]:
            del self.values[alias]

    @staticmethod
    def _stored_names(node) -> set[str]:
        """Names (re)bound anywhere inside `node`, including nested statements."""
        names = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, (ast.Store, ast.Del)):
                names.add(sub.id)
            elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(sub.name)
            elif isinstance(sub, ast.ExceptHandler) and sub.name:
                names.add(sub.name)
            elif isinstance(sub, (ast.MatchAs, ast.MatchStar)) and sub.name:
                names.add(sub.name)
            elif isinstance(sub, ast.MatchMapping) and sub.rest:
                names.add(sub.rest)
            elif isinstance(sub, (ast.Import, ast.ImportFrom)):
                names.update(a.asname or a.name.split(".")[0] for a in sub.names)
        return names

    _NARROWING_ONLY = {"filter", "where", "filter_by", "join", "outerjoin", "execution_options",
                       "limit", "offset", "order_by", "options", "distinct"}

    def _loop_narrowed_queries(self, loop) -> set[str]:
        """Query variables a loop only ever rebinds as `q = q.<narrowing method>(...)`.
        Such a rebinding keeps the model and can only shrink the selected rows, so the
        loop-entry query still over-approximates every iteration; it need not be forgotten.
        Any other kind of rebinding inside the loop disqualifies the name."""
        def narrows(name, value):
            node = value.value if isinstance(value, ast.Await) else value
            if not isinstance(node, ast.Call):
                return False
            while isinstance(node, ast.Call):
                if not (isinstance(node.func, ast.Attribute) and node.func.attr in self._NARROWING_ONLY):
                    return False
                node = node.func.value
            return isinstance(node, ast.Name) and node.id == name

        ok, bad = set(), set()
        for sub in ast.walk(loop):
            if isinstance(sub, (ast.Assign, ast.AnnAssign)) and sub.value is not None:
                targets = sub.targets if isinstance(sub, ast.Assign) else [sub.target]
                if len(targets) == 1 and isinstance(targets[0], ast.Name):
                    name = targets[0].id
                    (ok if name in self.queries and narrows(name, sub.value) else bad).add(name)
                    continue
                bad |= self._stored_names(sub)
        simple = {id(t) for sub in ast.walk(loop) if isinstance(sub, (ast.Assign, ast.AnnAssign))
                  for t in (sub.targets if isinstance(sub, ast.Assign) else [sub.target])
                  if isinstance(t, ast.Name)}
        for sub in ast.walk(loop):  # every other way of binding a name disqualifies it
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, (ast.Store, ast.Del)) and id(sub) not in simple:
                bad.add(sub.id)
            elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bad.add(sub.name)
        return ok - bad - self._untrackable

    def _spine(self, e):
        """The call nodes that make up a query expression `query()` understood."""
        if isinstance(e, ast.Await):
            e = e.value
        if not isinstance(e, ast.Call):
            return
        yield e
        f = e.func
        if isinstance(f, ast.Attribute):
            recv = _dotted(f.value)
            if recv in self.db_vars:
                if f.attr in ("execute", "scalars", "scalar", "exec") and e.args:
                    yield from self._spine(e.args[0])
                return
            yield from self._spine(f.value)

    def _mark_spine(self, e):
        for node in self._spine(e):
            self._visited.add(id(node))

    def _totality_sweep(self):
        """Soundness spine.  Every call in the function body (nested functions, lambdas
        and comprehensions included) that was not positively modeled must be PROVEN
        effect-free, otherwise it becomes an effect-capable opaque.  The same holds for
        attribute/item writes that could be writes to an untracked ORM row."""
        if self.index is None:
            return
        purity, ctx = self.index.purity, self._pctx()
        tainted = frozenset(self._query_names)
        dangerous = self._dangerous_names()
        for stmt in self.fn.body:
            for node in ast.walk(stmt):
                if id(node) in self._visited:
                    continue
                if isinstance(node, ast.Call):
                    if self._session_lifecycle(node):
                        continue
                    free, deps = purity.call_free_deps(ctx, node, tainted, dangerous)
                    if not free:
                        name = _dotted(node.func) or ast.unparse(node.func)[:80]
                        self._opaque(f"{name}(...)", "unvisited_call", node.lineno)
                    self._assume_declared(deps)
                elif (isinstance(node, (ast.Attribute, ast.Subscript))
                        and isinstance(node.ctx, (ast.Store, ast.Del))):
                    if not purity.store_free(ctx, node):
                        self._opaque(f"{ast.unparse(node)[:80]} = ...", "untracked_write",
                                     node.lineno, block=False)
                elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                    # iterating a legacy Query object executes it
                    if any(isinstance(n, ast.Name) and n.id in tainted for n in ast.walk(node.iter)
                           ) and not isinstance(node.iter, ast.Call):
                        self._opaque(f"iterate {ast.unparse(node.iter)[:60]}", "unvisited_call",
                                     getattr(node, "lineno", self.fn.lineno))

    def _snapshot(self) -> _AnalysisState:
        return _AnalysisState(
            list(self.global_guards), copy.deepcopy(self.rows), copy.deepcopy(self.creates),
            copy.deepcopy(self.queries), copy.deepcopy(self.query_results), copy.deepcopy(self.values),
            dict(self.var_types), set(self.updated), dict(self.unresolved_values),
            self.global_assumed_from,
        )

    def _restore(self, state: _AnalysisState):
        self.global_guards = list(state.global_guards)
        self.rows = copy.deepcopy(state.rows)
        self.creates = copy.deepcopy(state.creates)
        self.queries = copy.deepcopy(state.queries)
        self.query_results = copy.deepcopy(state.query_results)
        self.values = copy.deepcopy(state.values)
        self.var_types = dict(state.var_types)
        self.updated = set(state.updated)
        self.unresolved_values = dict(state.unresolved_values)
        self.global_assumed_from = state.global_assumed_from

    @staticmethod
    def _common_lists(lists: list[list]) -> list:
        if not lists:
            return []
        return [item for item in lists[0] if all(item in other for other in lists[1:])]

    def _merge_row_bindings(self, bindings: list[dict]) -> dict:
        first = copy.deepcopy(bindings[0])
        if len(bindings) == 1:
            return first
        if all(row["model"] == first["model"] and row["selector"] == first["selector"]
               and row.get("guards", []) == first.get("guards", [])
               and row.get("effect_id") == first.get("effect_id")
               and row.get("assumed_from") == first.get("assumed_from")
               and row.get("read_emitted", False) == first.get("read_emitted", False)
               for row in bindings[1:]):
            # Every path holds the very same binding (the branches did not touch this
            # row).  Keep it as is: re-folding `or(S, S)` at each merge would double the
            # selector for every later branch.
            return first
        touched = [air.and_(*row.get("guards", []), row["selector"]) for row in bindings]
        if all(row["model"] == first["model"] for row in bindings):
            first["selector"] = air.or_(*touched)
            first["guards"] = []
        else:
            # A Python local rebound to different model types cannot be represented as one row.
            # Keep the first binding but remove all restrictions; effects from each branch were
            # already emitted independently.
            first["selector"] = True
            first["guards"] = []
        first["assumed_from"] = next(
            (row.get("assumed_from") for row in bindings if row.get("assumed_from")), None
        )
        first["effect"] = None
        first["read_emitted"] = all(row.get("read_emitted", False) for row in bindings)
        return first

    def _merge_states(self, states: list[_AnalysisState]) -> _AnalysisState:
        if len(states) == 1:
            return copy.deepcopy(states[0])
        merged = copy.deepcopy(states[0])
        merged.global_guards = self._common_lists([state.global_guards for state in states])
        merged.global_assumed_from = next(
            (state.global_assumed_from for state in states if state.global_assumed_from), None
        )

        row_names = set().union(*(state.rows for state in states))
        merged.rows = {}
        for name in row_names:
            bindings = [state.rows[name] for state in states if name in state.rows]
            merged.rows[name] = self._merge_row_bindings(bindings)

        create_names = set().union(*(state.creates for state in states))
        merged.creates = {}
        for name in create_names:
            variants = [state.creates[name] for state in states if name in state.creates]
            item = copy.deepcopy(variants[0])
            item["fields"] = self._common_lists([variant["fields"] for variant in variants])
            merged.creates[name] = item

        query_names = set().union(*(state.queries for state in states))
        merged.queries = {}
        for name in query_names:
            variants = [state.queries[name] for state in states if name in state.queries]
            item = copy.deepcopy(variants[0])
            if all(variant.model == item.model for variant in variants):
                item.conds = self._common_lists([variant.conds for variant in variants])
                item.executed = all(variant.executed for variant in variants)
                item.effect_emitted = all(variant.effect_emitted for variant in variants)
                item.terminal = item.terminal if all(v.terminal == item.terminal for v in variants) else None
                merged.queries[name] = item

        result_names = set().union(*(state.query_results for state in states))
        merged.query_results = {}
        for name in result_names:
            variants = [state.query_results[name] for state in states if name in state.query_results]
            item = copy.deepcopy(variants[0])
            if all(variant.model == item.model for variant in variants):
                item.conds = self._common_lists([variant.conds for variant in variants])
                merged.query_results[name] = item

        value_names = set.intersection(*(set(state.values) for state in states)) if states else set()
        merged.values = {
            name: copy.deepcopy(states[0].values[name])
            for name in value_names
            if all(state.values[name] == states[0].values[name] for state in states)
        }
        type_names = set.intersection(*(set(state.var_types) for state in states)) if states else set()
        merged.var_types = {
            name: states[0].var_types[name]
            for name in type_names
            if all(state.var_types[name] == states[0].var_types[name] for state in states)
        }
        merged.updated = set.intersection(*(state.updated for state in states)) if states else set()
        unresolved_names = set().union(*(state.unresolved_values for state in states))
        merged.unresolved_values = {}
        for name in unresolved_names:
            for state in states:
                if name in state.unresolved_values:
                    merged.unresolved_values[name] = state.unresolved_values[name]
                    break
        return merged

    def _sync_row_effects(self):
        """Attach only guards common to every fall-through/return path to earlier row reads."""
        for row in self.rows.values():
            effect_id = row.get("effect_id")
            if effect_id is None:
                continue
            for effect in self.ep.effects:
                if getattr(effect, "_analysis_id", None) == effect_id:
                    effect.guards = list(row.get("guards", []))
                    # Branch merges fold per-path guards into row["selector"] and clear
                    # row["guards"]; the effect's selector must track that or the folded
                    # guard is silently dropped from the emitted effect.
                    if "selector" in row:
                        effect.selector = row["selector"]
                    effect.assumed_from = effect.assumed_from or row.get("assumed_from")

    def _finalize_returned_row(self):
        if not self.returned_rows or any(row is None for row in self.returned_rows):
            self.returned_row = None
            return
        rows = [row for row in self.returned_rows if row is not None]
        if rows and all(row["model"] == rows[0]["model"] for row in rows):
            self.returned_row = self._merge_row_bindings(rows)

    # ---------- signature: principal, db, params ----------
    def _signature(self):
        args = self.fn.args.args + self.fn.args.kwonlyargs
        defaults = [None] * (len(self.fn.args.args) - len(self.fn.args.defaults)) + \
            list(self.fn.args.defaults) + list(self.fn.args.kw_defaults)
        for arg, default in zip(args, defaults):
            if self.index is not None and arg.annotation is not None:
                annotation_type = self.index.annotation_type(self.module, arg.annotation)
                if annotation_type:
                    self.var_types[arg.arg] = annotation_type
            annotation_name = (_annotation_dotted(arg.annotation) or "").split(".")[-1]
            if annotation_name in CONTAINER_TYPES:
                self.var_types[arg.arg] = annotation_name
            dep = self._depends_target(default) or self._depends_target(arg.annotation)
            dep_module = self.module
            if dep is None and self.index is not None:
                dep = self.index.annotation_dependency(self.module, arg.annotation)
                dep_module = self.index.annotation_dependency_module(
                    self.module, arg.annotation) or self.module
            policy_dep = self.policy and dep in self.policy.principal_dependencies
            policy_type = self.policy and annotation_name in self.policy.principal_types
            superuser_dep = self.policy and dep in self.policy.superuser_dependencies
            superuser_type = self.policy and annotation_name in self.policy.superuser_types
            if dep is not None:
                low = dep.lower()
                # A parameter typed as a policy-protected resource (a model with rules,
                # e.g. a Flow) is the object under access, not the caller, even if the
                # dependency name happens to contain "user"/"auth". A name-only match must
                # also not overwrite an already-chosen principal (no last-wins); an
                # explicit policy declaration always wins.
                arg_type = self.var_types.get(arg.arg)
                arg_is_resource = bool(
                    arg_type and arg_type in self.models and self.policy
                    and any(res == arg_type for (res, _kind) in self.policy.rules)
                )
                user_token = ("user" in low) or ("principal" in low)
                token_match = user_token or ("auth" in low)
                # Exclude a resource-typed parameter matched only by a weak "auth" token
                # (e.g. require_flow_auth -> Flow). The authenticated-user convention
                # ("...user"/"...principal") still names the caller even when the user
                # model itself has policy rules. A name-only match never overwrites an
                # already-chosen principal (no last-wins); policy declarations always win.
                exclude_resource = arg_is_resource and not user_token
                if policy_dep or superuser_dep or (
                        token_match and not exclude_resource and self.principal is None):
                    self.principal = arg.arg
                    self.ep.principal_binding = arg.arg
                    self.ep.principal_via = "dependency"
                    if superuser_dep:
                        self.global_guards.append(air.eq(air.principal("is_superuser"), air.const(True)))
                        self.global_assumed_from = f"principal dependency {dep}"
                        self._assume(f"superuser:{dep}",
                                     f"dependency {dep} is declared to admit superusers only (policy)")
                    if not (policy_dep or superuser_dep):
                        # Chosen by NAME only, not declared in the policy.  The name is
                        # not evidence of what the body does: verify it before the body
                        # of the endpoint is analyzed (see _analyze_dependency).
                        self.unverified_principals.append((arg.arg, dep, dep_module))
                elif any(k in low for k in ("db", "session")):
                    self.db_vars.add(arg.arg)
                else:
                    # A dependency that may load and authorize a resource (the dominant
                    # FastAPI idiom, e.g. `flow: Flow = Depends(get_flow)`). Analyze its
                    # body so its row read and ownership guards are modeled, not ignored.
                    self.dependency_params.append((arg.arg, dep, dep_module))
                continue
            if policy_type or superuser_type:
                self.principal = arg.arg
                self.ep.principal_binding = arg.arg
                self.ep.principal_via = "dependency"
                if superuser_type:
                    self.global_guards.append(air.eq(air.principal("is_superuser"), air.const(True)))
                    self.global_assumed_from = f"principal type {annotation_name}"
                    self._assume(f"superuser:{annotation_name}",
                                 f"type {annotation_name} is declared to admit superusers only (policy)")
                continue
            tname = _dotted(arg.annotation) if arg.annotation is not None else None
            short = tname.split(".")[-1] if tname else None
            if arg.arg in self.path_params:
                self.ep.params[arg.arg] = air.Param(arg.arg, "path", TYPE_MAP.get(short, "other"))
            elif short in TYPE_MAP or short is None or self.helper_mode:
                self.ep.params[arg.arg] = air.Param(arg.arg, "query", TYPE_MAP.get(short, "other"))
            else:
                self.body_vars.add(arg.arg)

    @staticmethod
    def _depends_target(node):
        if node is None:
            return None
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and (_dotted(sub.func) or "").split(".")[-1] in ("Depends", "Security"):
                # `Depends()` with no argument injects the annotated class: still code
                # that runs before the handler, so it is a dependency we cannot name.
                return (_dotted(sub.args[0]) if sub.args else None) or "?"
        return None

    # ---------- terms and predicates ----------
    def term(self, e, query_model=None):
        if isinstance(e, ast.Constant) and e.value is not None:
            return air.const(e.value)
        if isinstance(e, ast.Name) and e.id in self.ep.params:
            return air.param(e.id)
        if isinstance(e, ast.Name) and e.id in self.values:
            value = self.values[e.id]
            if query_model is not None and "field" in value:
                return None  # a field of some other row is not a column of this query
            return value
        if isinstance(e, ast.Attribute) and isinstance(e.value, ast.Name):
            base = e.value.id
            if base == self.principal:
                return air.principal(e.attr)
            if base in self.body_vars:
                name = f"{base}.{e.attr}"
                self.ep.params.setdefault(name, air.Param(name, "body", "other"))
                return air.param(name)
            if base in self.models:
                if query_model is not None and base != query_model:
                    return None
                # `Model.col` is a column of the query being built; outside a query
                # (an `if` test) it names no row at all.
                return _FieldTerm(e.attr, None if query_model is not None else "?")
            if base in self.rows or base in self.creates:
                if query_model is not None:
                    # Selector/field context: `other_row.x` is a value we cannot express,
                    # NOT field x of the row being selected.
                    return None
                return _FieldTerm(e.attr, base)
        if (isinstance(e, ast.Call) and (_dotted(e.func) or "").split(".")[-1] == "col"
                and len(e.args) == 1):
            return self.term(e.args[0], query_model=query_model)
        if (isinstance(e, ast.Call) and _dotted(e.func) in ("str", "int", "UUID", "uuid.UUID")
                and len(e.args) == 1):
            return self.term(e.args[0], query_model=query_model)
        return None

    def cond(self, e, query_model=None):
        """Predicate for a filter/where clause."""
        self._mark_unresolved_uses(e, "row selector")
        self._mark_unresolved_calls(e, "row selector")
        if isinstance(e, ast.Compare) and len(e.ops) == 1 and isinstance(e.ops[0], ast.Eq):
            a = self.term(e.left, query_model=query_model)
            b = self.term(e.comparators[0], query_model=query_model)
            if a is None or b is None:
                raise _Unsupported("filter term")
            return air.eq(a, b)
        if isinstance(e, ast.BoolOp):
            parts = [self.cond(v, query_model=query_model) for v in e.values]
            return air.and_(*parts) if isinstance(e.op, ast.And) else air.or_(*parts)
        if isinstance(e, ast.BinOp) and isinstance(e.op, (ast.BitAnd, ast.BitOr)):
            left = self.cond(e.left, query_model=query_model)
            right = self.cond(e.right, query_model=query_model)
            return air.and_(left, right) if isinstance(e.op, ast.BitAnd) else air.or_(left, right)
        if isinstance(e, ast.Call) and _dotted(e.func) in ("and_", "sqlalchemy.and_"):
            return air.and_(*[self.cond(a, query_model=query_model) for a in e.args])
        if isinstance(e, ast.Call) and _dotted(e.func) in ("or_", "sqlalchemy.or_"):
            return air.or_(*[self.cond(a, query_model=query_model) for a in e.args])
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
        """Return a conservatively accumulated query, including named statements."""
        if isinstance(e, ast.Await):
            return self.query(e.value)
        if isinstance(e, ast.Name):
            state = self.queries.get(e.id) or self.query_results.get(e.id)
            if state:
                return _QueryState(
                    state.model, list(state.conds), state.terminal,
                    state.executed, state.effect_emitted,
                )
            return None
        if not isinstance(e, ast.Call):
            return None
        f = e.func
        dotted = _dotted(f)
        if isinstance(f, ast.Name) and f.id in ("select", "delete", "update") and e.args:
            target = _dotted(e.args[0]) or ""
            model = target.split(".", 1)[0]
            if model not in self.models:
                return None
            # `select(A, B)` reads rows of both models; a query state describes one.
            # Leave it unrecognised so it is reported as unmodeled rather than as A only.
            entities = {(_dotted(arg) or "").split(".", 1)[0] for arg in e.args}
            if len(entities & self.models) > 1:
                return None
            terminal = f.id if f.id in ("delete", "update") else None
            return _QueryState(model, terminal=terminal)
        if not isinstance(f, ast.Attribute):
            return None
        recv = _dotted(f.value)
        if f.attr == "query" and recv in self.db_vars and e.args:
            model = _dotted(e.args[0])
            return _QueryState(model) if model in self.models else None
        if f.attr == "get" and recv in self.db_vars and len(e.args) >= 2:
            model = _dotted(e.args[0])
            if model not in self.models:
                return None
            state = _QueryState(model, executed=True)
            self._mark_unresolved_uses(e.args[1], "row selector")
            term = self.term(e.args[1], query_model=model)
            if term is not None:
                state.conds.append(air.eq(air.fld("id"), term))
            return state
        if f.attr in ("execute", "scalars", "scalar", "exec") and recv in self.db_vars and e.args:
            state = self.query(e.args[0])
            if state:
                state.executed = True
            return state

        state = self.query(f.value)
        if state is None:
            return None
        if f.attr in ("filter", "where"):
            if self.conditional_depth == 0:
                for condition in e.args:
                    try:
                        state.conds.append(self.cond(condition, query_model=state.model))
                    except _Unsupported:
                        self.ep.unmodeled_checks.append(
                            air.UnmodeledCheck(f"query filter dropped: {ast.unparse(condition)[:120]}", e.lineno)
                        )
            else:
                self.ep.unmodeled_checks.append(
                    air.UnmodeledCheck(f"conditional query filter dropped: {ast.unparse(e)[:120]}", e.lineno)
                )
        elif f.attr == "filter_by":
            if self.conditional_depth == 0:
                for kw in e.keywords:
                    term = self.term(kw.value, query_model=state.model)
                    if kw.arg and term is not None:
                        state.conds.append(air.eq(air.fld(kw.arg), term))
        elif f.attr in ("delete", "update"):
            state.terminal = f.attr
            state.executed = True
        elif f.attr in QUERY_PASSTHROUGH:
            if f.attr in {"first", "one", "one_or_none", "scalar_one_or_none", "scalar_one", "all", "scalars", "scalar"}:
                state.executed = True
        elif f.attr in {"join", "outerjoin", "execution_options"}:
            pass
        else:
            return None
        return state

    @staticmethod
    def _req(t):
        if t is None:
            raise _Unsupported("term")
        return t

    # ---------- statements ----------
    def _block(self, stmts, *, conditional=False) -> bool:
        """Analyze until control exits. Return whether the block can fall through."""
        if conditional:
            self.conditional_depth += 1
        try:
            for s in stmts:
                if self._try_throw_collectors:
                    self._try_throw_collectors[-1].append(self._snapshot())
                try:
                    falls_through = self._stmt(s)
                except _Unsupported:
                    self.ep.unmodeled_checks.append(
                        air.UnmodeledCheck(ast.unparse(s)[:120], s.lineno)
                    )
                    falls_through = True
                if self._try_throw_collectors:
                    self._try_throw_collectors[-1].append(self._snapshot())
                if not falls_through:
                    return False
            return True
        finally:
            if conditional:
                self.conditional_depth -= 1

    def _condition_pred(self, test, truthy: bool):
        try:
            return self.pos(test) if truthy else self.neg(test)
        except _Unsupported:
            return None

    def _conjuncts(self, test, truthy: bool):
        """Split `test` (assumed to evaluate to `truthy`) into facts that ALL hold:
        `A and B` true -> A, B;  `A or B` false -> not A, not B;  `not X` flips."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            yield from self._conjuncts(test.operand, not truthy)
        elif isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And if truthy else ast.Or):
            for value in test.values:
                yield from self._conjuncts(value, truthy)
        else:
            yield test, truthy

    def _add_path_guard(self, test, truthy: bool, line: int):
        """Record what `test == truthy` proves on this path.

        AIR guards have one implicit row, so a fact may only be attached to a row when
        every field it mentions was read off that very row.  The condition is split into
        independent conjuncts first; a conjunct that mixes fields of several rows (or
        mentions a field with no nameable row) is attached to NOTHING.  Dropping a guard
        only widens the modeled access; attaching it to the wrong row would let Lean
        prove an access that was never checked."""
        for part, polarity in self._conjuncts(test, truthy):
            pred = self._condition_pred(part, polarity)
            if pred is None or pred is True:
                continue
            sources = _field_rows(pred)
            if not sources:
                self.global_guards.append(pred)  # only params / principal / constants
            elif len(sources) == 1 and next(iter(sources)) in self.rows:
                self.rows[next(iter(sources))]["guards"].append(pred)
            else:
                self.ep.unmodeled_checks.append(air.UnmodeledCheck(
                    f"cross-row guard dropped: {ast.unparse(part)[:100]}", line))

    def _analyze_if(self, s: ast.If) -> bool:
        base = self._snapshot()
        unresolved = self._unresolved_names(s.test)
        direct_denial = bool(not s.orelse and s.body and isinstance(s.body[-1], ast.Raise))
        if unresolved and not direct_denial:
            self._mark_unresolved_uses(s.test, "control flow")
        if not direct_denial:
            self._mark_unresolved_calls(s.test, "control flow")
        true_pred = self._condition_pred(s.test, True)
        false_pred = self._condition_pred(s.test, False)
        # For a bare `if X: raise`, only the fall-through (false) branch survives, so
        # a not-found check like `if doc is None: raise` is fully modeled as soon as
        # its false predicate is known; the raised branch's predicate is irrelevant and
        # must not be logged as a dropped check (which would spuriously demote findings).
        missing = (false_pred is None) if direct_denial else (true_pred is None or false_pred is None)
        if missing:
            self.ep.unmodeled_checks.append(
                air.UnmodeledCheck(ast.unparse(s.test)[:120], s.lineno)
            )

        self._restore(base)
        self._add_path_guard(s.test, True, s.lineno)
        true_falls = self._block(s.body, conditional=True)
        true_state = self._snapshot() if true_falls else None

        self._restore(base)
        self._add_path_guard(s.test, False, s.lineno)
        false_falls = self._block(s.orelse, conditional=True) if s.orelse else True
        false_state = self._snapshot() if false_falls else None

        fallthrough = [state for state in (true_state, false_state) if state is not None]
        if not fallthrough:
            self._restore(base)
            return False
        self._restore(self._merge_states(fallthrough))
        return True

    def _stmt(self, s):
        # A walrus anywhere in this statement rebinds its target to an unmodeled value.
        for sub in ast.walk(s):
            if isinstance(sub, ast.NamedExpr) and isinstance(sub.target, ast.Name):
                self._kill(sub.target.id)
        if isinstance(s, ast.If):
            return self._analyze_if(s)
        if isinstance(s, (ast.With, ast.AsyncWith, ast.For, ast.AsyncFor, ast.While)):
            if isinstance(s, (ast.For, ast.AsyncFor, ast.While)):
                # The body is analyzed once, from the loop-entry state.  Anything the
                # loop rebinds may hold a later iteration's value on entry, so forget it
                # first (the loop target included).
                narrowed = self._loop_narrowed_queries(s)
                for name in self._stored_names(s):
                    if name not in narrowed:
                        self._kill(name)
                base = self._snapshot()
                self._restore(base)
                self._block(s.body, conditional=True)
                body = self._snapshot()
                # Zero iterations is always possible; only facts common with the entry survive.
                self._restore(self._merge_states([base, body]))
            else:
                for item in s.items:
                    if item.optional_vars is not None:
                        for name in self._stored_names(item.optional_vars):
                            self._kill(name)
                return self._block(s.body)
            return True
        if isinstance(s, ast.Try):
            for handler in s.handlers:
                if handler.name:
                    self._kill(handler.name)
            start = self._snapshot()
            throw_points: list[_AnalysisState] = []
            self._try_throw_collectors.append(throw_points)
            self._restore(start)
            try_falls = self._block(s.body)
            self._try_throw_collectors.pop()
            normal = self._snapshot() if try_falls else None
            if normal is not None and s.orelse:
                self._restore(normal)
                normal = self._snapshot() if self._block(s.orelse) else None

            handler_states = []
            if s.handlers and throw_points:
                # Unknown exception hierarchies are treated as catchable. This deliberately
                # loses guards rather than inventing an uncaught path exit.
                handler_entry = self._merge_states(throw_points)
                for handler in s.handlers:
                    self._restore(handler_entry)
                    if self._block(handler.body, conditional=True):
                        handler_states.append(self._snapshot())

            fallthrough = ([normal] if normal is not None else []) + handler_states
            if s.finalbody:
                final_inputs = fallthrough or throw_points or [start]
                final_states = []
                for state in final_inputs:
                    self._restore(state)
                    if self._block(s.finalbody):
                        final_states.append(self._snapshot())
                fallthrough = final_states
            if not fallthrough:
                self._restore(start)
                return False
            self._restore(self._merge_states(fallthrough))
            return True
        if isinstance(s, ast.Raise):
            if self._try_throw_collectors:
                self._try_throw_collectors[-1].append(self._snapshot())
            return False
        if isinstance(s, ast.Assign) and len(s.targets) == 1:
            self._assign(s.targets[0], s.value, s.lineno)
            return True
        if isinstance(s, ast.AnnAssign) and s.value is not None:
            self._assign(s.target, s.value, s.lineno)
            return True
        if isinstance(s, ast.Expr) and isinstance(s.value, (ast.Call, ast.Await)):
            call = s.value.value if isinstance(s.value, ast.Await) else s.value
            if isinstance(call, ast.Call):
                self._call(call, s.lineno)
            return True
        if isinstance(s, ast.Return):
            returned = None
            if s.value is not None:
                self._mark_unresolved_uses(s.value, "returned_response")
                self._mark_unresolved_calls(s.value, "returned response")
                value = s.value.value if isinstance(s.value, ast.Await) else s.value
                if isinstance(value, ast.Name) and value.id in self.rows:
                    returned = copy.deepcopy(self.rows[value.id])
                self._expr_effects(s.value, s.lineno)
            self.returned_rows.append(returned)
            self.return_states.append(self._snapshot())
            return False
        # Any other statement (multi-target/augmented assignment, del, nested def,
        # match, import, ...) is not modeled.  Its calls are classified by the totality
        # sweep; here we only make sure no stale binding survives it.
        for name in self._stored_names(s):
            self._kill(name)
        return True

    def _guard(self, test):
        refs = {n.id for n in ast.walk(test) if isinstance(n, ast.Name) and n.id in self.rows}
        g = self.neg(test)
        if refs:
            for v in refs:
                self.rows[v]["guards"].append(g)
                if self.rows[v].get("effect") is not None:
                    self.rows[v]["effect"].guards.append(g)
        else:
            self.global_guards.append(g)

    def _assign(self, target, value, line):
        if isinstance(value, ast.Await):
            value = value.value
        if isinstance(target, ast.Name):
            name = target.id
            tables = (self.rows, self.creates, self.queries, self.query_results, self.values)
            before = [table.get(name) for table in tables]
            self.var_types.pop(name, None)
            self._assign_name(target, value, line)
            # A binding the assignment did not replace is stale: the name now holds
            # something else.  Never let the old row/query/value answer for it.
            for table, old in zip(tables, before):
                if old is not None and table.get(name) is old:
                    table.pop(name)
            if self.rows.get(name) is not before[0] or self.creates.get(name) is not before[1]:
                self.updated.discard(name)
                self._forget_fields_of(name)
            if name in self.queries:
                self._query_names.add(name)
            if name in self._untrackable:
                self._kill(name)
            return
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            self._assign_attribute(target, value, line)
            return
        # Tuple/list unpacking, starred or subscript targets: the names are rebound to
        # values we do not model.  The right-hand side is left to the totality sweep,
        # which records an effect-capable opaque unless it is proven effect-free.
        for stored in self._stored_names(target):
            self._kill(stored)

    def _assign_name(self, target, value, line):
        if isinstance(value, (ast.Dict, ast.List, ast.Set, ast.Tuple)):
            self.var_types[target.id] = type(value).__name__.lower()
            self.unresolved_values.pop(target.id, None)
            return
        q = self.query(value) if isinstance(value, (ast.Call, ast.Name)) else None
        if q:
            self._mark_spine(value)
            if not q.executed:
                self.queries[target.id] = q
                return
            selector = air.and_(*q.conds)
            effect = None
            if not q.effect_emitted:
                effect = self._emit(
                    q.terminal or "read", q.model, selector,
                    list(self.global_guards), line,
                )
                q.effect_emitted = True
            if q.terminal is None and self._returns_row(value):
                self.rows[target.id] = {
                    "model": q.model, "selector": selector,
                    "guards": list(self.global_guards), "line": line,
                    "assumed_from": None, "read_emitted": True,
                    "effect": effect,
                    "effect_id": getattr(effect, "_analysis_id", None),
                }
            elif q.terminal is None:
                self.query_results[target.id] = q
            return
        if isinstance(value, ast.Call) and _dotted(value.func) in self.models:
            for kw in value.keywords:
                self._mark_unresolved_uses(kw.value, "database_mutation")
                self._mark_unresolved_calls(kw.value, "database mutation")
            fields = [air.eq(air.fld(kw.arg), t) for kw in value.keywords
                      if kw.arg and (t := self.term(kw.value, query_model=_dotted(value.func))) is not None]
            self.creates[target.id] = {"model": _dotted(value.func), "fields": fields, "line": line}
            return
        if isinstance(value, ast.Call):
            constructor = (_dotted(value.func) or "").split(".")[-1]
            if constructor in CONTAINER_TYPES:
                # A container wrapper such as `list(await session.exec(select(X)))`
                # still performs the inner query; extract its effects before binding
                # the variable as an opaque container.
                for inner in [*value.args, *(kw.value for kw in value.keywords)]:
                    if isinstance(inner, (ast.Call, ast.Await)):
                        self._expr_effects(inner, line)
                self.var_types[target.id] = constructor
                self.unresolved_values.pop(target.id, None)
                return
            if self.index is not None and constructor in self.index.classes:
                self.var_types[target.id] = constructor
        value_term = self.term(value)
        if value_term is not None:
            self.values[target.id] = value_term
            return
        if isinstance(value, ast.Call):
            before = (len(self.ep.effects), len(self.ep.opaque), len(self.rows))
            self._helper(target.id, value, line)
            after = (len(self.ep.effects), len(self.ep.opaque), len(self.rows))
            if (before == after and not self._ignored_call(_dotted(value.func))
                    and not self._known_value_call(value)):
                self.unresolved_values[target.id] = (
                    f"{_dotted(value.func) or ast.unparse(value.func)}(...)", line
                )
        return

    def _assign_attribute(self, target, value, line):
        var = target.value.id
        if var in self.creates:
            self._visited.add(id(target))
            t = self.term(value, query_model=self.creates[var]["model"])
            if t is not None:
                self.creates[var]["fields"].append(air.eq(air.fld(target.attr), t))
        elif var in self.rows:
            self._visited.add(id(target))
            if var not in self.updated:
                self._mark_unresolved_uses(value, "database mutation")
                self._mark_unresolved_calls(value, "database mutation")
                r = self.rows[var]
                self.updated.add(var)
                self._emit("update", r["model"], r["selector"], list(r["guards"]), line, r["assumed_from"])

    @staticmethod
    def _returns_row(value):
        if not isinstance(value, ast.Call):
            return False
        # The terminal method decides; the receiver may be an awaited result, as in
        # `(await session.exec(stmt)).first()`, which has no dotted name.
        func = value.func
        name = func.attr if isinstance(func, ast.Attribute) else (_dotted(func) or "")
        return name in {"get", "first", "one", "one_or_none", "scalar", "scalar_one", "scalar_one_or_none"}

    def _ignored_call(self, name: str | None) -> bool:
        if not name:
            return False
        short = name.split(".")[-1]
        if short in IGNORED_CALLS or short in IGNORED_METHODS:
            return True
        base = name.rsplit(".", 1)[0] if "." in name else ""
        root = base.split(".", 1)[0]
        if short in LOG_METHODS and (root in {"logger", "log"} or root.endswith("logger")):
            return True
        if short in CONTAINER_METHODS and self.var_types.get(root) in CONTAINER_TYPES:
            return True
        # Policy `adapter.ignore_calls` is NOT consulted here by name: declarations are
        # call-level (binding + refusal, see _declaration) and handled where the call is.
        return False

    def _unresolved_names(self, node) -> set[str]:
        return {
            sub.id for sub in ast.walk(node)
            if isinstance(sub, ast.Name) and sub.id in self.unresolved_values
        }

    def _mark_unresolved_uses(self, node, use: str):
        for name in self._unresolved_names(node):
            call, line = self.unresolved_values[name]
            # Value-only: the producing call was classified for effects where it ran.
            self._opaque(call, f"unresolved_result_in_{use.replace(' ', '_')}", line, effects=False)

    def _known_value_call(self, call: ast.Call) -> bool:
        name = _dotted(call.func)
        if name in KNOWN_NON_DB_CALLS:
            return True
        if name and "." in name:
            receiver, method = name.rsplit(".", 1)
            receiver_type = self.var_types.get(receiver)
            if receiver_type is None and self.index is not None:
                receiver_type = self.index.global_types.get((self.module, receiver))
            if method in KNOWN_NON_DB_TYPED_METHODS.get(receiver_type or "", set()):
                return True
        if (name or "").split(".")[-1] in {"col", "and_", "or_"}:
            return True
        if self._ignored_call(name) or name in self.models:
            return True
        declared, refused = self._declaration(call)
        if declared and not refused:
            self._assume(f"ignore:{declared}", f"call {declared} is declared data-irrelevant in the "
                                               f"policy (adapter.ignore_calls); it was not analyzed")
            return True
        constructor = (name or "").split(".")[-1]
        if self.index is not None and constructor in self.index.classes:
            init_refs = [
                ref for ref in self.index.methods_by_name.get("__init__", [])
                if ref.owner_class == constructor
            ]
            if not init_refs or all(not self.index.function_may_touch_db(ref) for ref in init_refs):
                return True
        if name and name in self.summaries:
            return True
        if self._helper_key(call):
            return True
        if self.query(call) is not None:
            return True
        ref = self.index.resolve_function(
            self.module, name, self.var_types, self.owner_class
        ) if self.index else None
        if ref is not None:
            # Source was available and the repository relevance pass followed its callees.
            # DB-touching functions are modeled by _helper; non-DB functions are proven
            # non-relevant for object effects by the same pass.
            return True
        return False

    def _mark_unresolved_calls(self, node, use: str):
        for call in (sub for sub in ast.walk(node) if isinstance(sub, ast.Call)):
            if self._known_value_call(call):
                continue
            name = _dotted(call.func) or ast.unparse(call.func)
            display = f"{name}(...)"
            # Value-only: this records that the RESULT is unknown where it steers control
            # flow / a selector / the response.  Whether the call itself can touch data
            # is decided separately (it stays unvisited for the totality sweep).
            self._opaque(display, f"unresolved_result_in_{use.replace(' ', '_')}", call.lineno,
                         effects=False)

    def _helper_key(self, call) -> str | None:
        """The policy `helpers:` entry naming THIS call, bound by spelling or resolved
        identity (never a bare leaf that resolves to unrelated repository code)."""
        if not (self.policy and self.policy.helper_guards):
            return None
        if self.index is None:
            name = _dotted(call.func)
            return name if name in self.policy.helper_guards else None
        return self.index.purity.binding_key(self._pctx(), call, self.policy.helper_guards)

    def _trusted_helper(self, name: str | None, call) -> bool:
        if not self.policy or not name:
            return False
        key = self._helper_key(call)
        if key is None:
            return False
        self._assume(f"helper-guard:{key}",
                     f"helper {key} is declared in the policy to enforce a guard (not verified against its body)")
        refs = {n.id for n in ast.walk(call) if isinstance(n, ast.Name) and n.id in self.rows}
        if not refs:
            # User-declared trust (policy `helpers:`), unchanged: with no row argument the
            # declared guard is assumed for every later effect.  Results that rely on it
            # are always labelled SAFE (assumed), never SAFE.
            self.global_guards.append(self.policy.helper_guards[key])
            self.global_assumed_from = key
            return True
        guard = self.policy.helper_guards[key]
        for ref in refs:
            row = self.rows[ref]
            row["guards"].append(guard)
            row["assumed_from"] = key
            if row.get("effect") is not None:
                row["effect"].guards.append(guard)
                row["effect"].assumed_from = key
        return True

    @staticmethod
    def _bound_arguments(fn, call, skip_first: bool = False) -> dict[str, ast.AST]:
        positional = [*fn.args.posonlyargs, *fn.args.args]
        if skip_first:
            positional = positional[1:]  # bound method: self/cls is not a call argument
        params = [*positional, *fn.args.kwonlyargs]
        bound = {param.arg: value for param, value in zip(params, call.args)
                 if not isinstance(value, ast.Starred)}
        bound.update({kw.arg: kw.value for kw in call.keywords if kw.arg})
        return bound

    def _substitute_pred(self, pred, bound):
        """Instantiate helper parameters; unresolved terms widen the predicate."""
        if pred is True or pred is False:
            return pred
        (kind, value), = pred.items()
        if kind in ("and", "or"):
            parts = [self._substitute_pred(part, bound) for part in value]
            return air.and_(*parts) if kind == "and" else air.or_(*parts)

        def term(item):
            if isinstance(item, dict) and "param" in item:
                actual = bound.get(item["param"])
                actual_term = self.term(actual) if actual is not None else None
                if actual_term is not None and "field" in actual_term:
                    # A field of one of the CALLER's rows is not a field of the row this
                    # predicate is about: widen rather than conflate the two rows.
                    return None
                return actual_term
            return item

        if kind == "eq":
            left, right = (term(item) for item in value)
            return air.eq(left, right) if left is not None and right is not None else True
        if kind == "member":
            subject, obj = term(value[1]), term(value[2])
            return air.member(value[0], subject, obj) if subject is not None and obj is not None else True
        return True

    def _analyze_repo_helper(self, ref, var, call, line, skip_first: bool = False) -> bool:
        qualified = ".".join(x for x in (ref.module, ref.owner_class, ref.node.name) if x)
        if self.depth >= 3 or qualified in self.call_stack:
            self._opaque(f"{qualified}(...)", "recursion_or_depth_limit", line)
            return True

        bound = self._bound_arguments(ref.node, call, skip_first)
        if any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg is None for k in call.keywords):
            # *args/**kwargs at the call site: positional binding is unknown, so helper
            # parameters must not be instantiated from (possibly shifted) arguments.
            bound = {}
        roles = []
        has_row_arg = False
        for name, actual in bound.items():
            role = "value"
            if isinstance(actual, ast.Name) and actual.id in self.db_vars:
                role = "db"
            elif isinstance(actual, ast.Name) and actual.id == self.principal:
                role = "principal"
            elif isinstance(actual, ast.Name) and actual.id in self.rows:
                role = f"row:{self.rows[actual.id]['model']}"
                has_row_arg = True
            roles.append((name, role))
        # The child's analysis is a function of the argument roles and, for row
        # arguments, of the state each row is seeded with (model, selector, guards).
        seeds = tuple(sorted(
            (name, repr((self.rows[bound[name].id]["model"], self.rows[bound[name].id]["selector"],
                         self.rows[bound[name].id]["guards"])))
            for name, role in roles if role.startswith("row:")))
        cache_key = (qualified, tuple(sorted(roles)), skip_first, seeds)
        analysis = self.index.summary_cache.get(cache_key)

        if analysis is None:
            child = _FunctionAnalyzer(
                ref.node, self.models, self.summaries, ref.file, "HELPER", qualified,
                index=self.index, module=ref.module, policy=self.policy,
                depth=self.depth + 1, call_stack=self.call_stack | {qualified}, helper_mode=True,
                analyze_dependencies=False,
            )
            child.owner_class = ref.owner_class
            if ref.owner_class:
                child.db_vars.update({"self.session", "self.db"})
            child._signature()
            seeded_guards = {}
            for name, role in roles:
                if role == "db":
                    child.db_vars.add(name)
                    child.ep.params.pop(name, None)
                elif role == "principal":
                    child.principal = name
                    child.ep.principal_binding = name
                    child.ep.principal_via = "external"
                    child.ep.params.pop(name, None)
                elif role.startswith("row:"):
                    actual = bound[name]
                    source = self.rows[actual.id]
                    child.rows[name] = copy.deepcopy(source)
                    child.rows[name]["effect"] = None
                    child.rows[name]["effect_id"] = None
                    child.rows[name]["read_emitted"] = True
                    child.ep.params.pop(name, None)
                    seeded_guards[name] = copy.deepcopy(source.get("guards", []))
            child._analyze_body()
            row_guards = {}
            for name, original in seeded_guards.items():
                if name not in child.rows:
                    continue
                added = [guard for guard in child.rows[name].get("guards", []) if guard not in original]
                if added:
                    row_guards[name] = added
            analysis = _HelperAnalysis(
                copy.deepcopy(child.ep.effects), copy.deepcopy(child.ep.opaque),
                copy.deepcopy(child.ep.unmodeled_checks), copy.deepcopy(child.returned_row),
                copy.deepcopy(row_guards), dict(child.ep.assumptions),
            )
            self.index.summary_cache[cache_key] = copy.deepcopy(analysis)

        copied_effects = []
        effect_by_child_id = {}
        for effect in analysis.effects:
            child_id = getattr(effect, "_analysis_id", None)
            copied = copy.deepcopy(effect)
            copied.selector = self._substitute_pred(copied.selector, bound)
            copied.guards = [
                *self.global_guards,
                *(self._substitute_pred(g, bound) for g in copied.guards),
            ]
            copied.assumed_from = copied.assumed_from or self.global_assumed_from
            copied.line = line
            copied._analysis_id = self._next_effect_id
            self._next_effect_id += 1
            self.ep.effects.append(copied)
            copied_effects.append(copied)
            if child_id is not None:
                effect_by_child_id[child_id] = copied
        for opaque in analysis.opaque:
            self.ep.opaque.append(air.Opaque(opaque.call, opaque.reason, line, opaque.may_block,
                                             opaque.may_have_effects))
        for check in analysis.unmodeled_checks:
            self.ep.unmodeled_checks.append(air.UnmodeledCheck(check.expression, line))
        for key, reason in analysis.assumptions.items():
            self._assume(key, reason)  # whatever the helper's model assumed, the caller assumes

        for param_name, guards in analysis.row_guards.items():
            actual = bound.get(param_name)
            if not isinstance(actual, ast.Name) or actual.id not in self.rows:
                continue
            row = self.rows[actual.id]
            for guard in guards:
                instantiated = self._substitute_pred(guard, bound)
                if instantiated is not True:
                    row["guards"].append(instantiated)

        if analysis.returned_row is not None and var != "_ret":
            row = copy.deepcopy(analysis.returned_row)
            row["selector"] = self._substitute_pred(row["selector"], bound)
            row["guards"] = [
                *self.global_guards,
                *(self._substitute_pred(g, bound) for g in row["guards"]),
            ]
            row["assumed_from"] = row.get("assumed_from") or self.global_assumed_from
            row["line"] = line
            row["read_emitted"] = True
            row["effect"] = effect_by_child_id.get(row.get("effect_id"))
            row["effect_id"] = getattr(row["effect"], "_analysis_id", None)
            self.rows[var] = row
        return bool(analysis.effects or analysis.opaque or analysis.returned_row or analysis.row_guards)

    def _dependency_declaration(self, dep_name, qualified, ref) -> str | None:
        """The ignore_calls entry that may suppress dependency `dep_name`, or None.

        Same rules as a call (Purity.declaration_for): bound by spelling or resolved
        identity, a bare leaf only when the dependency's source is unreadable (2b);
        refuted when its visible body reads or writes the database (2c); refused when
        FastAPI hands it a database handle, i.e. it declares a db/session parameter
        (2a) -- then it is analyzed like any other dependency."""
        names = self.policy.ignored_calls if self.policy else set()
        if not names:
            return None
        leaf = dep_name.split(".")[-1]
        if dep_name in names:
            key = dep_name
        elif qualified in names:
            key = qualified
        elif leaf in names and ref is None:
            key = leaf
        else:
            return None
        if ref is None:
            return key  # unreadable: the declaration is the only knowledge we have
        if self.index.function_may_touch_db(ref):
            return None
        args = [*ref.node.args.posonlyargs, *ref.node.args.args, *ref.node.args.kwonlyargs]
        defaults = [None] * (len(ref.node.args.posonlyargs) + len(ref.node.args.args)
                             - len(ref.node.args.defaults)) + list(ref.node.args.defaults) \
            + list(ref.node.args.kw_defaults)
        for arg, default in zip(args, defaults):
            ann = (_annotation_dotted(arg.annotation) or "").lower()
            dep = (self._depends_target(default) or self._depends_target(arg.annotation)
                   or self.index.annotation_dependency(ref.module, arg.annotation) or "")
            low = dep.split(".")[-1].lower()
            if arg.arg in {"db", "session"} or "session" in ann or "db" in low or "session" in low:
                return None
        return key

    def _analyze_dependency(self, var, dep_name, dep_module=None, as_principal=False):
        """Model a `Depends(get_x)` parameter: its body's row read and the ownership
        guards it enforces, mapped onto the endpoint variable `var`. If the dependency
        loads a resource we cannot see into, mark it opaque (UNKNOWN), never silent.

        `as_principal`: `var` was taken to be the caller because of the dependency's NAME
        only.  That choice must not hide anything the dependency does:
          * unreadable body            -> opaque, the endpoint cannot be SAFE;
          * provably touches no table  -> a plain principal, nothing to add;
          * touches tables and itself depends on a principal -> it is a resource
            loader, not the caller: demoted to an ordinary dependency;
          * touches tables, no principal of its own -> stays the principal, but every
            effect in its body is emitted and checked.  Only the read of the row it
            returns gets the identity fact `row.<id> == principal.<id>`, which is what
            "this row is the caller" means; any other read/write is checked as is."""
        if self.index is None:
            return
        line = self.fn.lineno
        arg_type = self.var_types.get(var)
        typed_resource = bool(arg_type and arg_type in self.models)
        # Exact import resolution only: a dependency must never be matched to a
        # same-named method somewhere else in the repository.
        qualified_dep = self.index.resolve_name(dep_module or self.module, dep_name)
        ref = self.index.functions.get(qualified_dep)
        if ref is not None and ref.owner_class is not None:
            ref = None
        declared = self._dependency_declaration(dep_name, qualified_dep, ref)
        if declared:
            self._assume(f"ignore:{declared}", f"dependency {declared} is declared data-irrelevant in the "
                                               f"policy (adapter.ignore_calls); its body was not analyzed")
            return  # explicitly declared data-irrelevant in the policy
        if ref is None:
            # FastAPI runs this code before the handler.  If we cannot read it we
            # cannot rule out object access, whatever the parameter is typed as.
            self._opaque(f"{dep_name}(...)",
                         "principal_dependency_unverified" if as_principal
                         else "dependency_source_unavailable", line)
            return
        qualified = ".".join(x for x in (ref.module, ref.owner_class, ref.node.name) if x)
        if not self.index.purity._decorators_ok(ref.module, ref.node, ref.owner_class):
            self._opaque(f"{qualified}(...)", "decorated_helper", line)
            return
        if self.depth >= 3 or qualified in self.call_stack:
            self._opaque(f"{qualified}(...)", "recursion_or_depth_limit", line)
            return
        # A dependency's own sub-dependencies run too, and they are parameters, not calls
        # in its body: the effect-freedom proof of the body says nothing about them.
        dep_args = [*ref.node.args.posonlyargs, *ref.node.args.args, *ref.node.args.kwonlyargs]
        dep_defaults = [*ref.node.args.defaults, *ref.node.args.kw_defaults]
        has_subdependencies = any(
            self._depends_target(node) is not None
            or self.index.annotation_dependency(ref.module, node) is not None
            for node in [*dep_defaults, *(a.annotation for a in dep_args)] if node is not None)
        if (as_principal or not typed_resource) and not has_subdependencies:
            free, deps = self.index.purity.function_free_deps(ref.module, ref.node, ref.owner_class)
            if free:
                self._assume_declared(deps)
                return  # unable to touch the database (given `deps`, if any)

        child = _FunctionAnalyzer(
            ref.node, self.models, self.summaries, ref.file, "DEPENDENCY", qualified,
            index=self.index, module=ref.module, policy=self.policy,
            depth=self.depth + 1, call_stack=self.call_stack | {qualified}, helper_mode=True,
        )
        child.owner_class = ref.owner_class
        if ref.owner_class:
            child.db_vars.update({"self.session", "self.db"})
        child._signature()
        child._analyze_body()

        bind_row = True
        if as_principal:
            bind_row = False
            own_effects = [e for e in child.ep.effects
                           if getattr(e, "_analysis_id", None) not in child._principal_effect_ids]
            if own_effects and child.principal is not None:
                # Beyond fetching its own caller it touches data on that caller's
                # behalf: this is a resource loader, not the caller.
                bind_row = True
                if self.principal == var:
                    self.principal = None
                    self.ep.principal_binding = None
                    self.ep.principal_via = "none"

        returned = child.returned_row
        id_map = {}
        for effect in child.ep.effects:
            child_id = getattr(effect, "_analysis_id", None)
            copied = copy.deepcopy(effect)
            copied.guards = [*self.global_guards, *copied.guards]
            copied.assumed_from = copied.assumed_from or self.global_assumed_from
            copied.line = line
            copied._analysis_id = self._next_effect_id
            self._next_effect_id += 1
            self.ep.effects.append(copied)
            if child_id is not None:
                id_map[child_id] = copied
        for opaque in child.ep.opaque:
            self.ep.opaque.append(air.Opaque(opaque.call, opaque.reason, line, opaque.may_block,
                                             opaque.may_have_effects))
        for check in child.ep.unmodeled_checks:
            self.ep.unmodeled_checks.append(air.UnmodeledCheck(check.expression, line))
        for key, reason in child.ep.assumptions.items():
            self._assume(key, reason)

        if as_principal and not bind_row:
            self._principal_effect_ids.update(e._analysis_id for e in id_map.values())
            own_read = id_map.get(returned.get("effect_id")) if returned is not None else None
            id_attr = self.policy.id_attr if self.policy else "id"
            if (own_read is not None and own_read.kind == "read"
                    and not self._selects_by_request_id(own_read.selector, id_attr)):
                # "The row this dependency returns IS the caller" is what choosing it as
                # the principal means, but nothing proves it: record it as an explicit,
                # unreviewed assumption so the result is SAFE (assumed), never SAFE.
                # A row picked by an id taken from the request is a lookup of somebody,
                # not authentication of the caller: no identity fact for that.
                own_read.guards.append(air.eq(air.fld(id_attr), air.principal(id_attr)))
                own_read.assumed_from = (
                    f"principal dependency {dep_name} (matched by name; assumed to return the caller)")
                self._assume(f"principal-identity:{dep_name}",
                             f"principal dependency {dep_name} was matched by name and is assumed to "
                             f"return the caller (its returned row is taken to be the principal)")
            return
        if returned is not None:
            # Bind the returned row to ITS OWN read effect (via the child effect id),
            # not merely the first read of that model, or an unguarded sibling read of
            # the same model would be overwritten with the guarded selector -> false SAFE.
            copied_read = id_map.get(returned.get("effect_id"))
            row = copy.deepcopy(returned)
            row["guards"] = [*self.global_guards, *row.get("guards", [])]
            row["line"] = line
            row["read_emitted"] = True
            row["effect"] = copied_read
            row["effect_id"] = getattr(copied_read, "_analysis_id", None)
            self.rows[var] = row

    @staticmethod
    def _selects_by_request_id(selector, id_attr: str) -> bool:
        todo = [selector]
        while todo:
            node = todo.pop()
            if isinstance(node, dict):
                pair = node.get("eq")
                if pair and any(t.get("field") == id_attr for t in pair) and any("param" in t for t in pair):
                    return True
                todo.extend(node.values())
            elif isinstance(node, (list, tuple)):
                todo.extend(node)
        return False

    def _strict_ref(self, call):
        """The single repository definition `call` dispatches to, identified by import
        resolution or receiver type (never by method name alone).  None when the callee
        is unidentified or has overriding definitions."""
        if self.index is None:
            return None, False
        purity = self.index.purity
        targets = purity.dispatch_targets(self._pctx(), call)
        if not targets or len(targets) != 1:
            return None, False
        module, node, owner = targets[0]
        path = self.index.modules[module][0]
        ref = _FunctionRef(module, node, str(path.relative_to(self.index.repo)), owner)
        decorators = {_dotted(d) for d in node.decorator_list}
        bound_method = bool(owner) and "staticmethod" not in decorators and (
            "classmethod" in decorators or not purity.receiver_is_class_object(self._pctx(), call))
        return ref, bound_method

    def _session_lifecycle(self, call) -> bool:
        f = call.func
        return (isinstance(f, ast.Attribute) and _dotted(f.value) in self.db_vars
                and f.attr in {"commit", "flush", "refresh", "rollback", "close", "begin",
                               "begin_nested"})

    def _helper(self, var, call, line):
        """Classify one call that is not a recognised query.  Every exit either models
        the call, proves it effect-free, or records an effect-capable opaque."""
        self._visited.add(id(call))
        name = _dotted(call.func)
        display_name = name or ast.unparse(call.func)[:80]
        for value in [*call.args, *(kw.value for kw in call.keywords)]:
            if isinstance(value, (ast.Call, ast.Await)):
                self._expr_effects(value, line)
        declared, refused = self._declaration(call)
        if declared and not refused:
            self._assume(f"ignore:{declared}", f"call {declared} is declared data-irrelevant in the "
                                               f"policy (adapter.ignore_calls); it was not analyzed")
            return  # explicit, user-declared: data-irrelevant, and recorded as an assumption
        # A refused declaration (handed a db handle/row/query/callable, or refuted by the
        # callee's visible body) contributes nothing: classify the call as undeclared.
        if self._session_lifecycle(call):
            return  # transaction control on the session itself: no row is selected
        if self._trusted_helper(name, call):
            return
        if name in self.summaries:
            s = self.summaries[name]
            bound = {}
            for i, a in enumerate(call.args):
                if i < len(s.args):
                    bound[s.args[i]] = a
            for kw in call.keywords:
                bound[kw.arg] = kw.value
            sel = instantiate(
                s.selector,
                lambda n: self.term(bound[n], query_model=s.resource) if n in bound else None)
            if sel is None:
                self._opaque(f"{name}(...)", "unsupported_pattern", line)
                return
            label = None if s.reviewed else name
            if not s.reviewed:
                self._assume(f"summary:{name}",
                             f"helper {name} is modeled by a committed summary that has not been reviewed")
            if s.kind == "read":
                self.rows[var] = {"model": s.resource, "selector": sel,
                                  "guards": list(self.global_guards), "line": line,
                                  "assumed_from": label, "read_emitted": False,
                                  "effect": None, "effect_id": None}
            else:
                self._emit(s.kind, s.resource, sel, list(self.global_guards), line, label)
            return
        contains_query = any(
            isinstance(node, ast.Call)
            and ((_dotted(node.func) or "").split(".")[-1] in {"select", "query", "where", "filter"})
            for node in ast.walk(call)
        )
        query_names = {
            node.id for node in ast.walk(call)
            if isinstance(node, ast.Name) and node.id in (self.queries | self.query_results)
        }
        free = self._free(call)
        if (contains_query or query_names) and not free:
            self._opaque(f"{display_name}(...)", "dynamic_query_helper", line)
            return
        ref, bound_method = self._strict_ref(call)
        row_arg = any(
            isinstance(n, ast.Name) and n.id in self.rows
            for value in [*call.args, *(kw.value for kw in call.keywords)]
            for n in ast.walk(value)
        )
        if ref is not None and (row_arg or not free):
            if not self.index.purity._decorators_ok(ref.module, ref.node, ref.owner_class):
                # A wrapper we cannot read may add effects, swallow the helper's
                # denials, or not run the body at all: do not model the body as if it
                # were what the call does.
                self._opaque(f"{display_name}(...)", "decorated_helper", line)
                return
            # Inline the identified helper.  The child analyzer is total itself, so
            # whatever it could not model comes back as opaque.
            self._analyze_repo_helper(ref, var, call, line, bound_method)
            return
        if free:
            return  # proven unable to read or write a modeled table
        self._opaque(f"{display_name}(...)", "source_unavailable", line)

    def _update_row(self, var, line):
        if var in self.rows and var not in self.updated:
            r = self.rows[var]
            self.updated.add(var)
            self._emit("update", r["model"], r["selector"], list(r["guards"]), line, r["assumed_from"])

    def _call(self, call, line):
        f = call.func
        # setattr(row, "attr", value) mutates a tracked row; the attribute-assignment
        # path misses it and setattr is otherwise in IGNORED_CALLS.
        if (isinstance(f, ast.Name) and f.id == "setattr" and call.args
                and isinstance(call.args[0], ast.Name) and call.args[0].id in self.rows):
            self._visited.add(id(call))
            self._update_row(call.args[0].id, line)
            return
        if isinstance(f, ast.Attribute):
            recv = _dotted(f.value)
            # row.sqlmodel_update(...) writes new values into a tracked row in place.
            if f.attr == "sqlmodel_update" and recv in self.rows:
                self._visited.add(id(call))
                self._update_row(recv, line)
                return
            if recv in self.db_vars and call.args:
                arg = call.args[0]
                var = arg.id if isinstance(arg, ast.Name) else None
                if f.attr == "delete" and var in self.rows:
                    self._visited.add(id(call))
                    r = self.rows[var]
                    self._emit("delete", r["model"], r["selector"], list(r["guards"]), line, r["assumed_from"])
                    return
                if f.attr in ("add", "merge") and var in self.creates:
                    self._visited.add(id(call))
                    c = self.creates.pop(var)
                    self._emit("create", c["model"], air.and_(*c["fields"]), list(self.global_guards), line)
                    return
                if f.attr in ("add", "merge") and var in self.rows:
                    # Re-persisting an already-loaded row is a conservative update.
                    self._visited.add(id(call))
                    self._update_row(var, line)
                    return
        self._expr_effects(call, line)

    def _expr_effects(self, e, line):
        if isinstance(e, ast.Await):
            e = e.value
        if isinstance(e, ast.Call):
            q = self.query(e)
            if q:
                if q.executed:
                    # Only an EXECUTED query is accounted for.  A statement that is
                    # merely built here stays unvisited and is caught by the sweep.
                    self._mark_spine(e)
                if q.executed and not q.effect_emitted:
                    self._emit(q.terminal or "read", q.model, air.and_(*q.conds),
                               list(self.global_guards), line)
            elif _dotted(e.func) not in self.models:
                self._helper("_ret", e, line)

    def _emit(self, kind, model, selector, guards, line, assumed_from=None):
        effect = air.Effect(
            kind, model, selector, guards, line,
            assumed_from or self.global_assumed_from,
        )
        effect._analysis_id = self._next_effect_id
        self._next_effect_id += 1
        self.ep.effects.append(effect)
        return effect
