"""Effect-freedom oracle: can a call possibly read or write a modeled table?

The adapter must over-approximate what an endpoint can touch.  It may only leave a
call unmodeled *without* blocking SAFE when that call is provably unable to reach
the database.  This module is the single place that decision is made.

A call is effect-free only when its callee is IDENTIFIED and that identity is known
to be effect-free.  Identity comes from exactly three sources, never from the bare
name of a method on an unknown receiver:

  1. import resolution  - `uuid.uuid4`, `json.dumps`, `pathlib.Path` are resolved
     through the module's imports to a curated set of first-order stdlib/framework
     callables that never invoke their arguments;
  2. receiver type      - `x.get(...)` is effect-free only if the static type of `x`
     is known (a literal, a builtin constructor, a declared annotation, a class
     field annotation, a return annotation) and that type's method is effect-free;
  3. transitive closure - a repository function is effect-free only if EVERY call in
     its body (including nested functions) is effect-free and it performs no
     attribute write on a possibly-ORM object.  An unresolved callee anywhere in the
     closure makes the function not effect-free.

Everything else is "not proven", and the adapter records a `may_have_effects` opaque.

Stated assumptions (what this oracle does NOT prove; they are the trust base):

  A1. Declared annotations are honest: a parameter, class field or return value
      annotated `dict`/`str`/`SomeRepoClass` holds an instance of that type or of a
      repository subclass of it (overrides in repository subclasses ARE checked).
  A2. Implicit dispatch is not modeled: operators, iteration, truthiness, `str()`
      and friends invoking dunder methods, `with obj:` / `await obj` on a non-call
      expression, property access, descriptors, `__getattr__` on untyped objects,
      metaclasses, ORM lazy loading triggered by attribute access, and callbacks
      registered globally (ORM event listeners, structlog processors, middleware,
      signal/atexit hooks).  Repository `logging` handlers ARE checked.
  A3. Code outside the scanned repository reaches modeled tables only through a
      database handle, statement, or callable handed to it.  Only curated
      first-order callables are trusted on that basis; unknown external callables
      are never assumed effect-free.
  A4. No monkeypatching / rebinding of module attributes at runtime, and classes
      defined outside the repository do not subclass repository classes.
"""
from __future__ import annotations

import ast
import builtins as _builtins
from types import SimpleNamespace

# --------------------------------------------------------------------------- tables

BUILTIN_VALUE_TYPES = {
    "str", "bytes", "int", "float", "bool", "dict", "list", "set", "tuple", "frozenset",
    "bytearray", "complex",
}

# Builtins that never call their arguments (other than through the dunder protocol, A2).
# Deliberately absent: map, filter, sorted/min/max with key= (kw-guarded below), iter
# with a sentinel, exec, eval, compile, __import__, open, input, setattr/delattr (handled
# as mutations), getattr on unknown objects is allowed (returns a value, calls nothing).
FIRST_ORDER_BUILTINS = BUILTIN_VALUE_TYPES | {
    "len", "repr", "isinstance", "issubclass", "hasattr", "getattr", "type", "id", "hash",
    "abs", "round", "divmod", "pow", "ord", "chr", "bin", "hex", "oct", "format", "ascii",
    "range", "enumerate", "zip", "reversed", "sum", "any", "all", "slice", "print", "vars",
    "dir", "callable", "iter", "next", "min", "max", "sorted", "super", "object",
    "memoryview", "anext", "aiter",
}

# Keyword arguments through which a first-order-looking callable accepts a callback.
HIGHER_ORDER_KW = {
    "key", "default", "cls", "object_hook", "object_pairs_hook", "parse_float", "parse_int",
    "parse_constant", "target", "callback", "func", "default_factory", "initializer",
    "factory", "custom_encoder", "encoder", "decoder", "hook", "handler", "repl", "loader",
    "dumps", "loads", "background", "on_error", "exception_handler",
}

# External value classes: constructing one and calling its methods cannot touch the DB.
EXT_VALUE_CLASSES = {
    "pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.PurePosixPath",
    "uuid.UUID", "datetime.datetime", "datetime.date", "datetime.time", "datetime.timedelta",
    "datetime.timezone", "decimal.Decimal", "io.BytesIO", "io.StringIO",
    "collections.OrderedDict", "collections.Counter", "collections.deque",
    "asyncio.Queue", "asyncio.Event", "asyncio.Lock", "asyncio.Semaphore",
    "zipfile.ZipFile", "fractions.Fraction", "contextvars.ContextVar", "logging.LogRecord",
}
# Methods of value types that take a callback positionally.
VAL_HIGHER_ORDER_METHODS = {
    ("re.Pattern", "sub"), ("re.Pattern", "subn"),
    ("asyncio.Task", "add_done_callback"), ("asyncio.Future", "add_done_callback"),
}

# Whole external modules whose public callables are first-order (given the kw guard).
EXT_FREE_MODULES = (
    "uuid.", "json.", "math.", "time.", "datetime.", "hashlib.", "hmac.", "base64.",
    "binascii.", "secrets.", "string.", "os.path.", "posixpath.", "urllib.parse.", "html.",
    "textwrap.", "mimetypes.", "shlex.", "struct.", "zlib.", "unicodedata.", "decimal.",
    "fractions.", "random.", "statistics.", "copy.", "pathlib.", "io.", "zipfile.",
    "logging.", "warnings.", "traceback.", "http.", "ipaddress.", "enum.",
    "fastapi.responses.", "starlette.responses.", "fastapi.exceptions.",
    "starlette.exceptions.", "fastapi.status.", "starlette.status.",
)
EXT_FREE_EXACT = {
    "re.compile", "re.match", "re.search", "re.fullmatch", "re.findall", "re.finditer",
    "re.split", "re.escape",
    "os.getenv", "os.environ.get", "os.fspath", "os.listdir", "os.makedirs", "os.remove",
    "os.unlink", "os.stat", "os.getcwd", "os.getpid",
    "typing.cast", "dataclasses.asdict", "dataclasses.replace", "dataclasses.field",
    "dataclasses.fields", "dataclasses.is_dataclass",
    "collections.OrderedDict", "collections.Counter", "collections.deque",
    "collections.namedtuple", "collections.ChainMap",
    "itertools.chain", "itertools.chain.from_iterable", "itertools.islice",
    "itertools.product", "itertools.zip_longest", "itertools.count", "itertools.repeat",
    "itertools.cycle", "itertools.combinations", "itertools.permutations",
    "itertools.pairwise", "itertools.batched",
    # asyncio entries below take awaitables/values, never bare callables.
    "asyncio.sleep", "asyncio.gather", "asyncio.create_task", "asyncio.ensure_future",
    "asyncio.wait_for", "asyncio.shield", "asyncio.wait", "asyncio.as_completed",
    "asyncio.Queue", "asyncio.Event", "asyncio.Lock", "asyncio.Semaphore",
    "asyncio.get_running_loop", "asyncio.get_event_loop", "asyncio.current_task",
    "asyncio.timeout", "asyncio.iscoroutine", "asyncio.iscoroutinefunction",
    "asyncio.CancelledError", "asyncio.TimeoutError", "asyncio.QueueEmpty",
    "contextlib.suppress", "contextlib.nullcontext",
    "fastapi.HTTPException", "fastapi.Response", "fastapi.Query", "fastapi.Path",
    "fastapi.Body", "fastapi.Header", "fastapi.Cookie", "fastapi.File", "fastapi.Form",
    "fastapi.encoders.jsonable_encoder", "starlette.requests.Request",
    "pydantic.Field", "pydantic.ConfigDict", "pydantic.SecretStr", "pydantic.ValidationError",
    "pydantic.PrivateAttr", "sqlmodel.Field",
    "structlog.get_logger", "structlog.stdlib.get_logger", "logging.getLogger",
    "contextvars.ContextVar",
}
EXT_NOT_FREE = {"re.sub", "re.subn", "copy.replace", "logging.config.dictConfig",
                "io.open", "pathlib.Path.walk"}

# SQL *expression* constructors: they build a predicate/column expression and execute
# nothing.  select/insert/update/delete/text/exists are deliberately absent.
SQL_EXPR_FREE = {
    "sqlmodel.col", "sqlmodel.and_", "sqlmodel.or_", "sqlmodel.not_", "sqlmodel.desc",
    "sqlmodel.asc", "sqlmodel.func", "sqlmodel.cast", "sqlmodel.literal", "sqlmodel.case",
    "sqlmodel.null", "sqlmodel.true", "sqlmodel.false", "sqlmodel.distinct",
    "sqlmodel.nulls_last", "sqlmodel.nulls_first", "sqlmodel.extract", "sqlmodel.between",
    "sqlmodel.tuple_",
}
SQL_EXPR_FREE |= {name.replace("sqlmodel.", "sqlalchemy.") for name in SQL_EXPR_FREE}
SQL_EXPR_FREE |= {name.replace("sqlmodel.", "sqlalchemy.sql.") for name in SQL_EXPR_FREE
                  if name.startswith("sqlmodel.")}

LOGGER_FACTORIES = {"structlog.get_logger", "structlog.stdlib.get_logger", "logging.getLogger"}
LOGGER_OBJECTS = {"loguru.logger"}
LOGGER_TYPES = {"structlog.BoundLogger", "structlog.stdlib.BoundLogger", "logging.Logger",
                "loguru.Logger"}

# External return types worth knowing (identity -> value type).
EXT_RETURNS = {
    "uuid.uuid4": "uuid.UUID", "uuid.uuid1": "uuid.UUID", "uuid.uuid5": "uuid.UUID",
    "os.getenv": "str", "os.path.join": "str", "os.path.basename": "str",
    "os.path.dirname": "str", "os.path.realpath": "str", "os.path.abspath": "str",
    "os.path.exists": "bool", "json.dumps": "str", "time.time": "float",
    "time.monotonic": "float", "time.perf_counter": "float",
    "datetime.datetime.now": "datetime.datetime", "datetime.datetime.utcnow": "datetime.datetime",
    "re.compile": "re.Pattern", "hashlib.sha256": "hashlib.hash", "hashlib.md5": "hashlib.hash",
    "base64.b64encode": "bytes", "base64.b64decode": "bytes",
    "base64.urlsafe_b64encode": "bytes", "base64.urlsafe_b64decode": "bytes",
    "secrets.token_urlsafe": "str", "secrets.token_hex": "str", "traceback.format_exc": "str",
    "urllib.parse.quote": "str", "urllib.parse.unquote": "str",
}
STR_TO_STR = {"strip", "lstrip", "rstrip", "lower", "upper", "title", "replace", "format",
              "join", "removeprefix", "removesuffix", "casefold", "capitalize", "zfill",
              "center", "ljust", "rjust", "swapcase", "expandtabs"}
VAL_METHOD_RETURNS = {("str", m): "str" for m in STR_TO_STR}
VAL_METHOD_RETURNS.update({
    ("str", "split"): "list", ("str", "rsplit"): "list", ("str", "splitlines"): "list",
    ("str", "encode"): "bytes", ("bytes", "decode"): "str", ("str", "startswith"): "bool",
    ("str", "endswith"): "bool", ("str", "isdigit"): "bool",
    ("bytes", "hex"): "str", ("uuid.UUID", "hex"): "str", ("hashlib.hash", "hexdigest"): "str",
    ("hashlib.hash", "digest"): "bytes", ("datetime.datetime", "isoformat"): "str",
    ("datetime.datetime", "timestamp"): "float", ("datetime.datetime", "replace"): "datetime.datetime",
    ("datetime.datetime", "astimezone"): "datetime.datetime",
    ("dict", "keys"): "dictview", ("dict", "values"): "dictview", ("dict", "items"): "dictview",
    ("dict", "copy"): "dict", ("list", "copy"): "list", ("set", "copy"): "set",
    ("set", "union"): "set", ("set", "intersection"): "set", ("set", "difference"): "set",
    ("io.BytesIO", "getvalue"): "bytes", ("io.BytesIO", "read"): "bytes",
    ("io.StringIO", "getvalue"): "str", ("io.StringIO", "read"): "str",
})
for _m in ("expanduser", "resolve", "absolute", "with_suffix", "with_name", "joinpath",
           "with_stem", "relative_to"):
    VAL_METHOD_RETURNS[("pathlib.Path", _m)] = "pathlib.Path"
for _m in ("exists", "is_dir", "is_file", "is_absolute", "is_symlink"):
    VAL_METHOD_RETURNS[("pathlib.Path", _m)] = "bool"
VAL_METHOD_RETURNS.update({("pathlib.Path", "read_text"): "str", ("pathlib.Path", "read_bytes"): "bytes",
                           ("pathlib.Path", "as_posix"): "str"})

TYPING_CONCRETE = {"typing.Dict": "dict", "typing.List": "list", "typing.Set": "set",
                   "typing.Tuple": "tuple", "typing.FrozenSet": "frozenset",
                   "typing.Text": "str"}
TYPING_WRAPPERS = {"typing.Optional", "typing.Annotated", "typing.Union", "typing.Final",
                   "typing.ClassVar", "typing_extensions.Annotated"}

# Framework request/response objects.  Their own methods are first-order; the listed
# attributes are plain data containers.  `.state`, `.app`, `.scope` are NOT listed: they
# can hold arbitrary application objects.
EXT_INSTANCE_TYPES = {
    "fastapi.Request", "starlette.requests.Request", "fastapi.WebSocket",
    "starlette.websockets.WebSocket", "fastapi.Response", "starlette.responses.Response",
    "fastapi.UploadFile", "starlette.datastructures.UploadFile",
    "starlette.requests.HTTPConnection",
} | {f"{m}.{n}" for m in ("fastapi.responses", "starlette.responses")
     for n in ("Response", "JSONResponse", "HTMLResponse", "PlainTextResponse",
               "RedirectResponse", "StreamingResponse", "FileResponse", "ORJSONResponse")}
EXT_INSTANCE_DATA_ATTRS = {"headers", "cookies", "query_params", "path_params", "url",
                           "base_url", "method", "client", "filename", "content_type",
                           "size", "status_code", "media_type", "body"}
ROUTER_TYPES = {"fastapi.APIRouter", "fastapi.FastAPI", "fastapi.routing.APIRouter",
                "fastapi.applications.FastAPI"}
ROUTER_DECORATOR_METHODS = {"get", "post", "put", "patch", "delete", "head", "options",
                            "api_route", "websocket", "on_event", "exception_handler"}

# Bases a repository class may inherit from without making inherited behaviour unknown.
EXT_BASE_OK_PREFIX = ("pydantic.", "pydantic_settings.", "sqlmodel.", "enum.", "typing.",
                      "typing_extensions.", "abc.", "collections.abc.", "dataclasses.",
                      "logging.")
EXT_BASE_OK_EXACT = {"fastapi.HTTPException", "starlette.exceptions.HTTPException",
                     "sqlalchemy.orm.DeclarativeBase", "sqlalchemy.orm.DeclarativeBaseNoMeta",
                     "sqlalchemy.orm.MappedAsDataclass"}
# `Base = declarative_base()`: a module global that is a trusted declarative base class.
DECLARATIVE_FACTORIES = {"sqlalchemy.orm.declarative_base",
                         "sqlalchemy.ext.declarative.declarative_base"}
PYDANTIC_READONLY_METHODS = {"model_dump", "model_dump_json", "dict", "json", "model_copy",
                             "copy"}
PYDANTIC_CLASS_METHODS = {"model_validate", "model_validate_json", "model_construct",
                          "from_orm", "parse_obj", "model_json_schema", "model_rebuild",
                          "construct"}
CONSTRUCTION_METHODS = {"__init__", "__new__", "__post_init__", "model_post_init",
                        "__attrs_post_init__", "__init_subclass__", "__set_name__"}
DECORATOR_OK = {
    "functools.wraps", "functools.cache", "functools.lru_cache", "contextlib.contextmanager",
    "contextlib.asynccontextmanager", "abc.abstractmethod", "typing.overload", "typing.final",
    "typing.override", "typing_extensions.override", "typing.no_type_check",
    "pydantic.field_validator", "pydantic.model_validator", "pydantic.validator",
    "pydantic.root_validator", "pydantic.field_serializer", "pydantic.model_serializer",
    "dataclasses.dataclass",
}
CLASS_DECORATOR_OK = {"dataclasses.dataclass", "typing.final", "typing.runtime_checkable",
                      "enum.unique", "functools.total_ordering"}


def dotted(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _is_exception_builtin(name: str) -> bool:
    obj = getattr(_builtins, name, None)
    return isinstance(obj, type) and issubclass(obj, BaseException)


class _Ctx:
    """Static, flow- and scope-insensitive facts about one function body."""

    def __init__(self, module: str, fn, owner: str | None):
        self.module = module
        self.fn = fn
        self.owner = owner            # qualified name of the enclosing class, if a method
        self.bindings: dict[str, list] = {}
        self.name_types: dict[str, object] = {}
        # Provenance of the typing done in this function: ids of `returns_type`
        # assumptions any inferred type here rests on.  Types are memoised per name, so
        # the dependency is kept per function and never cleared.
        self.type_deps: set = set()
        self.self_name = None
        self.cls_name = None
        if fn is not None:
            self._collect(fn)

    def _bind(self, name, kind, payload=None):
        self.bindings.setdefault(name, []).append((kind, payload))

    def _collect(self, fn):
        decorators = {dotted(d) for d in fn.decorator_list}
        args = fn.args
        positional = [*args.posonlyargs, *args.args]
        for i, arg in enumerate([*positional, *args.kwonlyargs]):
            if i == 0 and self.owner and positional and arg is positional[0]:
                if "staticmethod" not in decorators:
                    if "classmethod" in decorators:
                        self.cls_name = arg.arg
                    else:
                        self.self_name = arg.arg
                    self._bind(arg.arg, "self")
                    continue
            self._bind(arg.arg, "param", arg.annotation)
        # *args is always a real tuple and **kwargs a real dict, whatever is passed.
        if args.vararg is not None:
            self._bind(args.vararg.arg, "exact", ("val", "tuple"))
        if args.kwarg is not None:
            self._bind(args.kwarg.arg, "exact", ("val", "dict"))
        for stmt in fn.body:
            for node in ast.walk(stmt):
                self._collect_node(node)

    def _collect_node(self, node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._bind(node.name, "def", node)
            a = node.args
            for arg in [*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg]:
                if arg is not None:
                    self._bind(arg.arg, "other")
        elif isinstance(node, ast.Lambda):
            a = node.args
            for arg in [*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg]:
                if arg is not None:
                    self._bind(arg.arg, "other")
        elif isinstance(node, ast.ClassDef):
            self._bind(node.name, "other")
        elif isinstance(node, ast.With):
            for item in node.items:
                if isinstance(item.optional_vars, ast.Name):
                    self._bind(item.optional_vars.id, "with", item.context_expr)
        elif isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                self._bind(node.targets[0].id, "assign", (node.value, None))
            # other target shapes are picked up as plain Store names below
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                self._bind(node.target.id, "assign", (node.value, node.annotation))
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                self._bind(node.target.id, "aug")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                self._bind(alias.asname or alias.name.split(".")[0], "import", node)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                self._bind(name, "other")
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                self._bind(node.name, "other")
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)):
            if node.name:
                self._bind(node.name, "other")
        elif isinstance(node, ast.MatchMapping):
            if node.rest:
                self._bind(node.rest, "other")
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            self._bind(node.id, "store", node)

    def finalize(self):
        """A simple-assignment target is recorded twice (assign + store); drop the echo."""
        for name, items in self.bindings.items():
            assigns = sum(1 for kind, _ in items if kind in ("assign", "aug", "with"))
            stores = [item for item in items if item[0] == "store"]
            keep = [item for item in items if item[0] != "store"]
            # every "assign" produced exactly one matching Store name node
            extra = len(stores) - assigns
            keep.extend([("other", None)] * max(extra, 0))
            self.bindings[name] = keep


class Purity:
    def __init__(self, index, models: set[str], policy=None, assumptions=None):
        self.index = index
        self.models = models
        # keyhole.assumptions.yaml: bound by resolved identity, see `assumption_for`.
        self.assumptions = assumptions
        # Calls the user explicitly declared data-irrelevant in the policy file.  They are
        # bound and screened by `declaration_for`, never matched here by bare name.
        self.declared_free = set(getattr(policy, "ignored_calls", ()) or ())
        # Names the CURRENT top-level call site must not hand to a declared call (db
        # handles, live queries, tracked rows); set by `call_free` for one call.
        self._extra_dangerous: frozenset = frozenset()
        self.repo_tops = {name.split(".")[0] for name in index.modules}
        self.class_defs: dict[str, tuple[str, ast.ClassDef]] = {}
        self.module_bind_count: dict[tuple[str, str], int] = {}
        self.module_globals: dict[tuple[str, str], tuple] = {}
        self.toplevel_funcs: dict[str, tuple[str, ast.AST]] = {}
        self._ctx_cache: dict[int, _Ctx] = {}
        self._module_ctx: dict[str, _Ctx] = {}
        # Every memoised "effect-free" verdict is stored WITH the declarations it rests
        # on: (free, frozenset of assumption ids).  A bare cached True would let a
        # user-declared irrelevance become an unlabelled "proof" for every caller.
        self._free_cache: dict[int, tuple[bool, frozenset]] = {}
        self._stack: list[int] = []
        self._tentative: set[int] = set()
        self._ctor_cache: dict[str, tuple[bool, frozenset]] = {}
        self._ctor_stack: set[str] = set()
        # Collector stack: the innermost set receives the id of every declaration used
        # while establishing the verdict currently being computed.
        self._deps: list[set] = []
        # `if TYPE_CHECKING:` imports: they name types used in annotations.  The names are
        # unbound at runtime, so they can only ever inform annotation types (A1).
        self.type_imports: dict[str, dict[str, str]] = {}
        # Modules containing `from x import *` anywhere: any otherwise-unbound name in
        # them may come from the star import, so nothing there is identified by name.
        self.star_modules: set[str] = set()
        for module, (path, tree) in index.modules.items():
            if any(isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)
                   for n in ast.walk(tree)):
                self.star_modules.add(module)
            self._index_module(module, tree)
            for node in tree.body:
                if isinstance(node, ast.If) and (dotted(node.test) or "").split(".")[-1] == "TYPE_CHECKING":
                    fake = ast.Module(body=[n for n in node.body
                                            if isinstance(n, (ast.Import, ast.ImportFrom))],
                                      type_ignores=[])
                    self.type_imports.setdefault(module, {}).update(
                        index._imports(module, path, fake))
        self.bases: dict[str, list] = {}
        self.subclasses: dict[str, set[str]] = {}
        for q, (module, node) in self.class_defs.items():
            resolved = []
            for base in node.bases:
                expr = base.value if isinstance(base, ast.Subscript) else base
                ident = self.identity(self.module_ctx(module), expr)
                resolved.append(ident)
                if ident and ident[0] in ("class", "builtin", "ext"):
                    self.subclasses.setdefault(ident[1], set()).add(q)
            self.bases[q] = resolved
        if self.assumptions:
            self.assumptions.resolve(self)   # digests + standing of every entry

    # ---------------------------------------------------------------- indexing
    def _index_module(self, module: str, tree):
        def bump(name):
            self.module_bind_count[(module, name)] = self.module_bind_count.get((module, name), 0) + 1

        def visit(stmts, top):
            for node in stmts:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    bump(node.name)
                    if top:
                        self.toplevel_funcs[f"{module}.{node.name}"] = (module, node)
                elif isinstance(node, ast.ClassDef):
                    bump(node.name)
                    if top:
                        self.class_defs[f"{module}.{node.name}"] = (module, node)
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    for alias in node.names:
                        bump(alias.asname or alias.name.split(".")[0])
                elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    simple = (len(targets) == 1 and isinstance(targets[0], ast.Name)
                              and not isinstance(node, ast.AugAssign))
                    for target in targets:
                        for sub in ast.walk(target):
                            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                                bump(sub.id)
                    if simple and top:
                        self.module_globals[(module, targets[0].id)] = (
                            node.value, getattr(node, "annotation", None))
                    elif simple:
                        bump(targets[0].id)  # conditional definition: treat as ambiguous
                else:
                    for sub in ast.walk(node):
                        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                            ast.Lambda)):
                            continue
                        if isinstance(sub, ast.Name) and isinstance(sub.ctx, (ast.Store, ast.Del)):
                            bump(sub.id)
                            bump(sub.id)
                    for field in ("body", "orelse", "finalbody"):
                        visit(getattr(node, field, []) or [], False)
                    for handler in getattr(node, "handlers", []) or []:
                        visit(handler.body, False)

        visit(tree.body, True)
        # `global x` writes from inside functions make the module binding ambiguous.
        for node in ast.walk(tree):
            if isinstance(node, ast.Global):
                for name in node.names:
                    bump(name)
                    bump(name)

    def _unique(self, qualified: str) -> bool:
        module, _, name = qualified.rpartition(".")
        return self.module_bind_count.get((module, name), 0) == 1

    def module_ctx(self, module: str) -> _Ctx:
        ctx = self._module_ctx.get(module)
        if ctx is None:
            ctx = self._module_ctx[module] = _Ctx(module, None, None)
        return ctx

    def ctx_for(self, module: str, fn, owner_class: str | None = None) -> _Ctx:
        ctx = self._ctx_cache.get(id(fn))
        if ctx is None:
            owner = f"{module}.{owner_class}" if owner_class else None
            if owner not in self.class_defs:
                owner = None
            ctx = _Ctx(module, fn, owner)
            ctx.finalize()
            self._ctx_cache[id(fn)] = ctx
        return ctx

    # ---------------------------------------------------------------- identity
    def _classify(self, qualified: str):
        """What a fully qualified dotted name denotes."""
        seen = set()
        qualified = self.index.resolve_qualified(qualified, seen)
        if qualified in self.toplevel_funcs:
            return ("func", qualified) if self._unique(qualified) else None
        if qualified in self.class_defs:
            return ("class", qualified) if self._unique(qualified) else None
        if qualified in self.index.modules:
            return ("module", qualified)
        top = qualified.split(".")[0]
        if top not in self.repo_tops:
            return ("ext", qualified)
        module, _, name = qualified.rpartition(".")
        if module in self.index.modules:
            if (module, name) in self.module_globals and (
                    self._unique(qualified) or self.module_globals[(module, name)][1] is not None):
                # a module variable: assigned once, or declared with an annotation (A1)
                return ("global", qualified)
            # method of a top-level class addressed as Class.method is handled by callers
        return None

    def _local_import_target(self, ctx: _Ctx, name: str, node) -> str | None:
        path = self.index.modules.get(ctx.module, (None, None))[0]
        if path is None:
            return None
        fake = ast.Module(body=[node], type_ignores=[])
        return self.index._imports(ctx.module, path, fake).get(name)

    def identity(self, ctx: _Ctx, expr):
        """('func'|'class'|'module'|'ext'|'builtin'|'global'|'localfn', name) or None."""
        if isinstance(expr, ast.Name):
            name = expr.id
            items = ctx.bindings.get(name)
            if items:
                kinds = {kind for kind, _ in items}
                if kinds == {"import"}:
                    targets = {self._local_import_target(ctx, name, node) for _, node in items}
                    if len(targets) == 1 and None not in targets:
                        return self._classify(targets.pop())
                    return None
                if kinds == {"def"}:
                    # an undecorated nested function: its body is walked with the
                    # enclosing function, so calling it adds nothing new
                    if all(not node.decorator_list for _, node in items):
                        return ("localfn", name)
                    return None
                if kinds == {"assign"} and all(
                        isinstance(payload[0], ast.Lambda) for _, payload in items):
                    return ("localfn", name)
                if kinds == {"self"} and name == ctx.cls_name and ctx.owner:
                    return ("class", ctx.owner)
                return None
            if ctx.module in self.star_modules:
                return None
            imported = (self.index.imports.get(ctx.module, {}).get(name)
                        or self.type_imports.get(ctx.module, {}).get(name))
            count = self.module_bind_count.get((ctx.module, name), 0)
            if imported is not None:
                return self._classify(imported) if count == 1 else None
            if count:
                return self._classify(f"{ctx.module}.{name}")
            if hasattr(_builtins, name):
                return ("builtin", name)
            return None
        if isinstance(expr, ast.Attribute):
            base = self.identity(ctx, expr.value)
            if base is None:
                return None
            if base[0] == "module":
                return self._classify(f"{base[1]}.{expr.attr}")
            if base[0] == "ext":
                return ("ext", f"{base[1]}.{expr.attr}")
            return None
        return None

    # ---------------------------------------------------------------- class hierarchy
    def _ancestors(self, q: str, seen=None) -> list[str] | None:
        """Repository ancestors of q (inclusive); None if any base is unidentified or an
        external base outside the trusted set."""
        seen = seen if seen is not None else []
        if q in seen:
            return seen
        seen.append(q)
        for ident in self.bases.get(q, []):
            if ident is None:
                return None
            kind, name = ident
            if kind == "class":
                if self._ancestors(name, seen) is None:
                    return None
            elif kind == "builtin":
                if not (name in BUILTIN_VALUE_TYPES or name == "object"
                        or _is_exception_builtin(name)):
                    return None
            elif kind == "ext":
                if not (name.startswith(EXT_BASE_OK_PREFIX) or name in EXT_BASE_OK_EXACT
                        or name in EXT_VALUE_CLASSES):
                    return None
            elif kind == "global":
                module, _, attr = name.rpartition(".")
                value = self.module_globals[(module, attr)][0]
                factory = (self.identity(self.module_ctx(module), value.func)
                           if isinstance(value, ast.Call) else None)
                if not (factory and factory[0] == "ext" and factory[1] in DECLARATIVE_FACTORIES):
                    return None
            else:
                return None
        return seen

    def _descendants(self, q: str) -> set[str]:
        out, todo = set(), [q]
        while todo:
            for sub in self.subclasses.get(todo.pop(), ()):
                if sub not in out:
                    out.add(sub)
                    todo.append(sub)
        return out

    def _hierarchy(self, q: str) -> list[str] | None:
        """Ancestors of q and of every repository descendant of q; None if untrusted."""
        out: list[str] = []
        for cls in [q, *sorted(self._descendants(q))]:
            if self._ancestors(cls, out) is None:
                return None
        return out

    def _methods(self, q: str, name: str) -> list:
        _module, node = self.class_defs[q]
        return [item for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name]

    def is_model_class(self, q: str) -> bool:
        ancestors = self._ancestors(q)
        if ancestors is None:
            return True  # unknown ancestry: assume it may be mapped
        for cls in ancestors:
            node = self.class_defs[cls][1]
            if node.name in self.models:
                return True
        return False

    def _is_mapped_column(self, q: str, attr: str) -> bool:
        """`Class.attr` is an instrumented column: the class itself is table-mapped and
        `attr` is an annotated (non-ClassVar) field declared in its trusted ancestry."""
        _module, node = self.class_defs[q]
        mapped = any(kw.arg == "table" for kw in node.keywords) or any(
            isinstance(item, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "__tablename__" for t in item.targets)
            for item in node.body)
        ancestors = self._ancestors(q)
        if not mapped or ancestors is None or self._class_dynamic(ancestors):
            return False
        declared = False
        for cls in ancestors:
            for item in self.class_defs[cls][1].body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == attr:
                    return False
                if isinstance(item, ast.Assign) and any(
                        isinstance(t, ast.Name) and t.id == attr for t in item.targets):
                    return False
                if (isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)
                        and item.target.id == attr):
                    if "ClassVar" in ast.unparse(item.annotation):
                        return False
                    declared = True
        return declared

    def scalar_primary_key(self, ctx, entity):
        """Resolve an explicit single-column primary key on a repository model."""
        ident = self.identity(ctx, entity)
        if not ident or ident[0] != "class":
            return None
        ancestors = self._ancestors(ident[1])
        if not ancestors:
            return None
        keys = set()
        declarations = set()
        repeated = set()
        for cls in ancestors:
            module, node = self.class_defs[cls]
            for item in node.body:
                if not isinstance(item, (ast.Assign, ast.AnnAssign)):
                    continue
                targets = item.targets if isinstance(item, ast.Assign) else [item.target]
                names = {t.id for t in targets if isinstance(t, ast.Name)}
                repeated.update(names & declarations)
                declarations.update(names)
                if "__table__" in names:
                    return None
                value = item.value
                if "__mapper_args__" in names:
                    # This warning setting has no bearing on the mapper's identity.
                    if not (isinstance(value, ast.Dict) and all(
                        isinstance(k, ast.Constant) and k.value == "confirm_deleted_rows"
                        and isinstance(v, ast.Constant) and isinstance(v.value, bool)
                        for k, v in zip(value.keys, value.values)
                    )):
                        return None
                if value is None:
                    continue
                for call in (n for n in ast.walk(value) if isinstance(n, ast.Call)):
                    factory = self.identity(self.module_ctx(module), call.func)
                    if ((dotted(call.func) or "").split(".")[-1] == "PrimaryKeyConstraint"
                            or (factory and factory[1].endswith(".PrimaryKeyConstraint"))
                            or any(kw.arg is None for kw in call.keywords)):
                        return None
                    flags = [kw.value for kw in call.keywords if kw.arg == "primary_key"]
                    if not flags:
                        continue
                    if not isinstance(flags[0], ast.Constant):
                        return None
                    if flags[0].value is False:
                        continue
                    if call is not value and not (
                        isinstance(value, ast.Call) and
                        self.identity(self.module_ctx(module), value.func) == ("ext", "sqlmodel.Field")
                        and any(kw.arg == "sa_column" and kw.value is call for kw in value.keywords)
                    ):
                        return None
                    if (flags[0].value is not True or factory not in {
                            ("ext", "sqlmodel.Field"), ("ext", "sqlalchemy.Column"),
                            ("ext", "sqlalchemy.orm.mapped_column")}
                            or len(targets) != 1 or not isinstance(targets[0], ast.Name)):
                        return None
                    keys.add(targets[0].id)
        return next(iter(keys)) if len(keys) == 1 and keys.isdisjoint(repeated) else None

    def _may_be_model_instance(self, q: str) -> bool:
        return any(self.is_model_class(cls) for cls in [q, *self._descendants(q)])

    def _class_dynamic(self, classes: list[str]) -> bool:
        return any(self._methods(cls, hook) for cls in classes
                   for hook in ("__getattr__", "__getattribute__", "__call__"))

    # ---------------------------------------------------------------- provenance
    def _note(self, deps):
        """Record that the verdict being computed depends on these declarations."""
        if self._deps and deps:
            self._deps[-1].update(deps)

    def _scoped(self, compute):
        """Run `compute()` with a fresh collector; return (ok, ids it depended on) and
        pass the ids on to the enclosing computation."""
        self._deps.append(set())
        try:
            ok = compute()
        finally:
            deps = frozenset(self._deps.pop())
        if ok:
            self._note(deps)
        return ok, (deps if ok else frozenset())

    def call_free_deps(self, ctx: "_Ctx", call: ast.Call, tainted: frozenset = frozenset(),
                       dangerous: frozenset = frozenset()):
        """(free, ids): `ids` is empty only when the call is PROVEN effect-free.  A
        non-empty set means "free, provided these declarations are true"."""
        return self._scoped(lambda: self.call_free(ctx, call, tainted, dangerous))

    def function_free_deps(self, module: str, fn, owner_class: str | None = None):
        return self._scoped(lambda: self.function_free(module, fn, owner_class))

    def class_ctor_free(self, q: str) -> bool:
        """Constructing an instance of q (or validating into it) runs no DB code."""
        if q in self._ctor_cache:
            ok, deps = self._ctor_cache[q]
            self._note(deps)
            return ok
        if q in self._ctor_stack:
            return True
        self._ctor_stack.add(q)
        try:
            ok, deps = self._scoped(lambda: self._class_ctor_free(q))
        finally:
            self._ctor_stack.discard(q)
        root = not self._stack and not self._ctor_stack
        if root:
            self._ctor_cache[q] = (ok, deps)
            if ok:
                # members of a cycle share the root's (superset) provenance
                for item in self._tentative:
                    self._free_cache[item] = (True, deps)
            self._tentative = set()
        elif not ok:
            self._ctor_cache[q] = (False, frozenset())
        return ok

    def _class_ctor_free(self, q: str) -> bool:
        ancestors = self._ancestors(q)
        if ancestors is None:
            return False
        for cls in ancestors:
            module, node = self.class_defs[cls]
            mctx = self.module_ctx(module)
            if any(kw.arg == "metaclass" for kw in node.keywords):
                meta = next(kw.value for kw in node.keywords if kw.arg == "metaclass")
                if self.identity(mctx, meta) not in (("ext", "abc.ABCMeta"),):
                    return False
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                ident = self.identity(mctx, target)
                if not (ident and ident[0] == "ext" and ident[1] in CLASS_DECORATOR_OK):
                    return False
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    runs_at_construction = item.name in CONSTRUCTION_METHODS or any(
                        any(tag in (dotted(d.func if isinstance(d, ast.Call) else d) or "").lower()
                            for tag in ("validator", "serializer", "computed", "default"))
                        for d in item.decorator_list)
                    if runs_at_construction and not self.function_free(module, item, node.name):
                        return False
                    continue
                if isinstance(item, ast.ClassDef):
                    continue
                if isinstance(item, ast.AnnAssign):
                    # A field typed as another repository class is constructed, validated
                    # and serialized together with this one.
                    for sub in ast.walk(item.annotation):
                        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                            try:
                                sub = ast.parse(sub.value, mode="eval").body
                            except SyntaxError:
                                return False
                        for leaf in ast.walk(sub):
                            if isinstance(leaf, (ast.Name, ast.Attribute)):
                                ident = self.identity(mctx, leaf)
                                if ident and ident[0] == "class" and not self.class_ctor_free(ident[1]):
                                    return False
                # class-body statements run at import, but default factories run per instance
                for sub in ast.walk(item):
                    if isinstance(sub, ast.Call):
                        for kw in sub.keywords:
                            if kw.arg in ("default_factory", "factory") and not self.callable_ref_free(
                                    mctx, kw.value):
                                return False
        return True

    # ---------------------------------------------------------------- types
    def ann_type(self, ctx: _Ctx, ann):
        if ann is None:
            return None
        if isinstance(ann, ast.Constant):
            if ann.value is None:
                return ("none",)
            if isinstance(ann.value, str):
                try:
                    return self.ann_type(ctx, ast.parse(ann.value, mode="eval").body)
                except SyntaxError:
                    return None
            return None
        if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
            return self._join_optional([self.ann_type(ctx, ann.left), self.ann_type(ctx, ann.right)])
        if isinstance(ann, ast.Subscript):
            ident = self.identity(ctx, ann.value)
            if ident and ident[0] == "ext" and ident[1] in TYPING_WRAPPERS:
                inner = ann.slice
                elts = inner.elts if isinstance(inner, ast.Tuple) else [inner]
                if ident[1].endswith("Annotated"):
                    return self.ann_type(ctx, elts[0])
                return self._join_optional([self.ann_type(ctx, e) for e in elts])
            return self.ann_type(ctx, ann.value)
        ident = self.identity(ctx, ann)
        if ident is None:
            return None
        kind, name = ident
        if kind == "global":
            # a module-level type alias, e.g. `FileName = Annotated[str, Depends(...)]`
            module, _, attr = name.rpartition(".")
            aliases = self.__dict__.setdefault("_alias_stack", set())
            if name in aliases or not self._unique(name):
                return None
            aliases.add(name)
            try:
                value = self.module_globals[(module, attr)][0]
                return self.ann_type(self.module_ctx(module), value) if value is not None else None
            finally:
                aliases.discard(name)
        if kind == "builtin":
            if _is_exception_builtin(name):
                return ("val", "exception")
            return ("val", name) if name in BUILTIN_VALUE_TYPES else None
        if kind == "class":
            return ("inst", name)
        if kind == "ext":
            if name in ("sqlmodel.ext.asyncio.session.AsyncSession", "sqlmodel.Session",
                        "sqlmodel.orm.session.Session") and not self.subclasses.get(name):
                # Receiver identity only. No session method is effect-free by virtue
                # of this type: the adapter still has to extract the query.
                return ("sqlmodel_session",)
            if name in EXT_BASE_OK_EXACT and "Exception" in name:
                return ("val", "exception")
            if name in TYPING_CONCRETE:
                return ("val", TYPING_CONCRETE[name])
            if name in EXT_VALUE_CLASSES:
                return ("val", name)
            if name in LOGGER_TYPES:
                return ("logger",)
            if name in EXT_INSTANCE_TYPES:
                return ("extinst", name)
        return None

    @staticmethod
    def _join_optional(types):
        concrete = [t for t in types if t != ("none",)]
        if len(concrete) != len([t for t in concrete if t is not None]):
            return None
        distinct = {t for t in concrete}
        return distinct.pop() if len(distinct) == 1 else None

    def name_type(self, ctx: _Ctx, name: str):
        if name in ctx.name_types:
            return ctx.name_types[name]
        items = ctx.bindings.get(name)
        if not items:
            return self._global_name_type(ctx, name)
        ctx.name_types[name] = None  # provisional: breaks cycles conservatively
        result = self._name_type(ctx, name, items)
        ctx.name_types[name] = result
        return result

    def _name_type(self, ctx, name, items):
        def mentions_self(expr):
            return any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(expr))

        first, deferred, augmented = [], [], False
        for kind, payload in items:
            if kind == "self":
                if name == ctx.self_name and ctx.owner:
                    first.append(("inst", ctx.owner))
                else:
                    return None
            elif kind == "param":
                first.append(self.ann_type(ctx, payload))
            elif kind == "exact":
                first.append(payload)
            elif kind == "with":
                first.append(self._entered_type(ctx, payload))
            elif kind == "aug":
                augmented = True
            elif kind == "assign":
                value, _annotation = payload
                if value is None:
                    continue  # bare annotation `x: T` binds nothing
                if mentions_self(value):
                    deferred.append(value)
                else:
                    first.append(self.etype(ctx, value))
            else:
                return None
        if not first or any(t is None for t in first):
            return None
        # `x = None` alongside `x = "a"`: a method call on the None value raises and
        # touches nothing, so the optional join is sound.
        candidate = self._join_optional(first)
        if candidate is None:
            return None
        # `x += y` keeps the type only where the in-place operator is total on the left
        # operand (list.__iadd__, dict.__ior__).  For str/int/set it can defer to the
        # right operand's reflected method and yield anything.
        if augmented and candidate not in (("val", "list"), ("val", "dict")):
            return None
        ctx.name_types[name] = candidate
        for value in deferred:
            if self.etype(ctx, value) not in (candidate, ("none",)):
                ctx.name_types[name] = None
                return None
        return candidate

    def _entered_type(self, ctx, expr):
        """A binary reader from a concrete pathlib constructor has a standard __enter__."""
        if not (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute)
                and expr.func.attr == "open" and len(expr.args) == 1 and not expr.keywords
                and isinstance(expr.args[0], ast.Constant) and expr.args[0].value == "rb"):
            return None
        receiver = expr.func.value
        ident = self.identity(ctx, receiver)
        if ident and ident[0] == "global" and self._unique(ident[1]):
            module, _, name = ident[1].rpartition(".")
            receiver = self.module_globals[module, name][0]
            ctx = self.module_ctx(module)
        if isinstance(receiver, ast.Call) and self.identity(ctx, receiver.func) == ("ext", "pathlib.Path"):
            return ("binary_file_reader",)
        return None

    def _global_name_type(self, ctx: _Ctx, name: str):
        ident = self.identity(ctx, ast.Name(id=name, ctx=ast.Load()))
        return self._identity_value_type(ident, ctx)

    def _identity_value_type(self, ident, ctx=None):
        result = self._identity_value_type_inner(ident)
        if ctx is not None and ident is not None and ident[0] == "global":
            # a module global typed through an assumption taints whoever reads it
            ctx.type_deps |= self.module_ctx(ident[1].rpartition(".")[0]).type_deps
        return result

    def _identity_value_type_inner(self, ident):
        if ident is None:
            return None
        kind, qualified = ident
        if kind == "ext":
            return ("logger",) if qualified in LOGGER_OBJECTS else None
        if kind != "global":
            return None
        module, _, name = qualified.rpartition(".")
        key = (module, name)
        memo = self.__dict__.setdefault("_global_types", {})
        if key in memo:
            return memo[key]
        memo[key] = None
        value, annotation = self.module_globals[key]
        mctx = self.module_ctx(module)
        result = None
        if annotation is not None:
            # Declared type (A1).  It also covers later `global x` rebinding.
            result = self.ann_type(mctx, annotation)
        elif value is not None and self._unique(qualified):
            result = self.etype(mctx, value)
        if result == ("none",):
            result = None
        memo[key] = result
        return result

    def _field_type(self, q: str, attr: str):
        """Declared type of instance attribute `attr` on class q, if every declaration in
        the hierarchy agrees and nothing in the hierarchy defines it as a method."""
        classes = self._hierarchy(q)
        if classes is None or self._class_dynamic(classes):
            return None
        found = []
        for cls in classes:
            module, node = self.class_defs[cls]
            mctx = self.module_ctx(module)
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if item.name == attr:
                        return None
                    if item.name == "__init__":
                        ictx = self.ctx_for(module, item, node.name)
                        for sub in ast.walk(item):
                            target = None
                            if isinstance(sub, ast.AnnAssign):
                                target, declared = sub.target, self.ann_type(ictx, sub.annotation)
                            elif isinstance(sub, ast.Assign) and len(sub.targets) == 1:
                                target, declared = sub.targets[0], None
                            if (isinstance(target, ast.Attribute) and target.attr == attr
                                    and isinstance(target.value, ast.Name)
                                    and target.value.id == ictx.self_name):
                                found.append(declared)
                elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    if item.target.id == attr:
                        found.append(self.ann_type(mctx, item.annotation))
                elif isinstance(item, ast.Assign):
                    if any(isinstance(t, ast.Name) and t.id == attr for t in item.targets):
                        found.append(None)
        if not found or any(t is None for t in found) or len(set(found)) != 1:
            return None
        return found[0] if found[0] != ("none",) else None

    def etype(self, ctx: _Ctx, e):
        """Static type of a value expression, or None when unknown."""
        if isinstance(e, ast.Await):
            return self._call_type(ctx, e.value, awaited=True) if isinstance(e.value, ast.Call) else None
        if isinstance(e, ast.Constant):
            if e.value is None:
                return ("none",)
            return ("val", type(e.value).__name__) if type(e.value).__name__ in BUILTIN_VALUE_TYPES else None
        if isinstance(e, ast.JoinedStr):
            return ("val", "str")
        if isinstance(e, (ast.Dict, ast.DictComp)):
            return ("val", "dict")
        if isinstance(e, (ast.List, ast.ListComp)):
            return ("val", "list")
        if isinstance(e, (ast.Set, ast.SetComp)):
            return ("val", "set")
        if isinstance(e, ast.Tuple):
            return ("val", "tuple")
        if isinstance(e, ast.Name):
            return self.name_type(ctx, e.id)
        if isinstance(e, ast.NamedExpr):
            return self.etype(ctx, e.value)
        if isinstance(e, ast.Compare):
            return None  # rich comparisons may return anything (SQL expressions do)
        if isinstance(e, ast.IfExp):
            return self._join_optional([self.etype(ctx, e.body), self.etype(ctx, e.orelse)])
        if isinstance(e, ast.BoolOp):
            types = [self.etype(ctx, v) for v in e.values]
            if any(t is None for t in types):
                return None
            return self._join_optional(types)
        if isinstance(e, ast.BinOp):
            left = self.etype(ctx, e.left)
            if left == ("val", "str") and isinstance(e.op, ast.Mod):
                return left
            if left == ("val", "pathlib.Path") and isinstance(e.op, ast.Div):
                return left
            if (left is not None and left[0] == "val" and left[1] in ("str", "bytes", "list", "tuple")
                    and isinstance(e.op, ast.Add) and self.etype(ctx, e.right) == left):
                return left
            return None
        if isinstance(e, ast.Subscript):
            base = self.etype(ctx, e.value)
            if base in (("val", "str"), ("val", "bytes")):
                return base
            return None
        if isinstance(e, ast.Attribute):
            ident = self.identity(ctx, e)
            if ident is not None:
                return self._identity_value_type(ident, ctx)
            base_ident = self.identity(ctx, e.value)
            if base_ident and base_ident[0] == "class":
                if self._is_mapped_column(base_ident[1], e.attr):
                    return ("sqlexpr",)  # Model.column: an instrumented attribute
                return None
            base = self.etype(ctx, e.value)
            if base is None:
                return None
            if base[0] == "inst":
                return self._field_type(base[1], e.attr)
            if base[0] == "extinst" and e.attr in EXT_INSTANCE_DATA_ATTRS:
                return ("val", "framework-data")
            if base == ("val", "pathlib.Path") and e.attr in ("parent",):
                return base
            if base == ("val", "pathlib.Path") and e.attr in ("name", "suffix", "stem"):
                return ("val", "str")
            return None
        if isinstance(e, ast.Call):
            return self._call_type(ctx, e, awaited=False)
        return None

    def exact_builtin(self, ctx: _Ctx, e, _seen=None) -> bool:
        """The value is an instance of EXACTLY a builtin type (never a subclass): it was
        produced by a literal, a comprehension, a builtin constructor call, or a local
        name only ever bound to such values.  Annotations never qualify."""
        if isinstance(e, (ast.JoinedStr, ast.Dict, ast.DictComp, ast.List, ast.ListComp,
                          ast.Set, ast.SetComp, ast.Tuple)):
            return True
        if isinstance(e, ast.Constant):
            return e.value is not None
        if isinstance(e, ast.Call):
            ident = self.identity(ctx, e.func)
            return bool(ident and ident[0] == "builtin" and ident[1] in BUILTIN_VALUE_TYPES)
        if isinstance(e, ast.Name):
            seen = _seen or set()
            if e.id in seen:
                return True
            items = ctx.bindings.get(e.id)
            if not items:
                return False
            for kind, payload in items:
                if kind == "exact" or kind == "aug":
                    continue
                if kind != "assign" or payload[0] is None:
                    return False
                if not self.exact_builtin(ctx, payload[0], seen | {e.id}):
                    return False
            return True
        return False

    def _call_type(self, ctx: _Ctx, call: ast.Call, awaited: bool):
        if self.assumptions and not self.__dict__.get("_typing_assumption"):
            self._typing_assumption = True   # binding a call types its receiver: no re-entry
            try:
                entry = self.assumption_for(ctx, call, "returns_type")
            finally:
                self._typing_assumption = False
            if entry is not None and entry.claim in self.class_defs:
                # Resolution fact: "this call returns an instance of that class".  From
                # here on the adapter analyses the class's real method bodies.
                ctx.type_deps.add(entry.key)
                return ("inst", entry.claim)
        ident = self.identity(ctx, self._callee(ctx, call))
        if ident is not None:
            kind, name = ident
            if awaited and kind != "func":
                return None
            if kind == "builtin":
                return ("val", name) if name in BUILTIN_VALUE_TYPES else None
            if kind == "class":
                return ("inst", name)
            if kind == "ext":
                if name in LOGGER_FACTORIES:
                    return ("logger",)
                if name in EXT_VALUE_CLASSES:
                    return ("val", name)
                if name in EXT_RETURNS:
                    return ("val", EXT_RETURNS[name])
                if name in SQL_EXPR_FREE or name.startswith(("sqlmodel.func.", "sqlalchemy.func.",
                                                              "sqlalchemy.sql.func.")):
                    return ("sqlexpr",)
                if name in ROUTER_TYPES:
                    return ("extinst", name)
                return None
            if kind == "func":
                module, node = self.toplevel_funcs[name]
                return self._return_type(module, node, awaited)
            return None
        if isinstance(call.func, ast.Attribute):
            attr = call.func.attr
            base_ident = self.identity(ctx, call.func.value)
            if base_ident and base_ident[0] == "class":
                defs = self._method_defs(base_ident[1], attr)
                if defs is None:
                    return None
                if not defs:
                    if attr in ("model_validate", "model_validate_json", "model_construct",
                                "from_orm", "parse_obj", "construct") and not awaited:
                        return ("inst", base_ident[1])
                    return None
                return self._agree([self._return_type(m, n, awaited) for m, n, _ in defs])
            base = self.etype(ctx, call.func.value)
            if base is None or awaited and base[0] != "inst":
                return None
            if base[0] == "val":
                returned = VAL_METHOD_RETURNS.get((base[1], attr))
                return ("val", returned) if returned else None
            if base[0] == "sqlexpr":
                return ("sqlexpr",)
            if base[0] == "logger":
                return ("logger",) if attr in ("bind", "new", "opt", "getChild") else None
            if base[0] == "inst":
                defs = self._method_defs(base[1], attr)
                if defs is None:
                    return None
                if not defs:
                    # read-only pydantic API inherited from a trusted base
                    if awaited or self._hierarchy(base[1]) is None:
                        return None
                    if attr in ("model_dump", "dict"):
                        return ("val", "dict")
                    if attr in ("model_dump_json", "json"):
                        return ("val", "str")
                    return None
                return self._agree([self._return_type(m, n, awaited) for m, n, _ in defs])
        return None

    @staticmethod
    def _agree(types):
        if not types or any(t is None for t in types) or len(set(types)) != 1:
            return None
        return types[0] if types[0] != ("none",) else None

    def _return_type(self, module: str, node, awaited: bool):
        is_async = isinstance(node, ast.AsyncFunctionDef)
        if is_async != awaited:
            return None
        if any(isinstance(sub, (ast.Yield, ast.YieldFrom)) for sub in ast.walk(node)):
            return None
        mctx = self.module_ctx(module)
        for dec in node.decorator_list:  # a decorator may change what the call returns
            ident = self.identity(mctx, dec)
            if ident not in (("builtin", "staticmethod"), ("builtin", "classmethod"),
                             ("ext", "abc.abstractmethod"), ("ext", "typing.override"),
                             ("ext", "typing_extensions.override"), ("ext", "typing.final")):
                return None
        result = self.ann_type(mctx, node.returns)
        return None if result == ("none",) else result

    def _method_defs(self, q: str, name: str):
        """All definitions `name` may dispatch to on an instance typed q: [(module, node,
        class name)].  None when the hierarchy is untrusted or dispatch is dynamic."""
        classes = self._hierarchy(q)
        if classes is None or self._class_dynamic(classes):
            return None
        out = []
        for cls in classes:
            module, node = self.class_defs[cls]
            for item in node.body:
                # `name = something` in a class body: not a def we can read.
                targets = (item.targets if isinstance(item, ast.Assign)
                           else [item.target] if isinstance(item, ast.AnnAssign) else [])
                if any(isinstance(t, ast.Name) and t.id == name for t in targets):
                    return None
            out.extend((module, item, node.name) for item in self._methods(cls, name))
        return out

    # ---------------------------------------------------------------- effect freedom
    def _decorators_ok(self, module: str, fn, owner_class) -> bool:
        mctx = self.module_ctx(module)
        for dec in fn.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            ident = self.identity(mctx, target)
            if ident and ident[0] == "builtin" and ident[1] in ("staticmethod", "classmethod"):
                continue  # `property` is deliberately absent: calling a property's value is unknown
            if ident and ident[0] == "ext" and ident[1] in DECORATOR_OK:
                continue
            if (isinstance(target, ast.Attribute) and target.attr in ROUTER_DECORATOR_METHODS
                    and (self.etype(mctx, target.value) or (None, None))[1] in ROUTER_TYPES):
                continue
            return False
        return True

    def function_free(self, module: str, fn, owner_class: str | None = None) -> bool:
        """True only if no call reachable from fn's body can touch the database."""
        key = id(fn)
        if key in self._free_cache:
            ok, deps = self._free_cache[key]
            self._note(deps)
            return ok
        if key in self._stack or key in self._tentative:
            # Coinductive assumption; only cached once the root succeeds.  Whatever this
            # node depended on was already passed up to the root's collector when it
            # was first computed, and the root's set is what every cycle member is
            # cached with.
            return True
        self._stack.append(key)
        try:
            ok, deps = self._scoped(lambda: self._body_free(module, fn, owner_class))
        finally:
            self._stack.pop()
        root = not self._stack and not self._ctor_stack
        if not ok:
            self._free_cache[key] = (False, frozenset())
        elif root:
            self._free_cache[key] = (True, deps)
            for item in self._tentative:
                self._free_cache[item] = (True, deps)
        else:
            self._tentative.add(key)
        if root:
            self._tentative = set()
        return ok

    def _body_free(self, module: str, fn, owner_class) -> bool:
        if not self._decorators_ok(module, fn, owner_class):
            return False
        ctx = self.ctx_for(module, fn, owner_class)
        for stmt in fn.body:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call):
                    if not self.call_free(ctx, node):
                        return False
                elif isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                        node.ctx, (ast.Store, ast.Del)):
                    if not self.store_free(ctx, node):
                        return False
        self._note(ctx.type_deps)   # every type this proof leaned on, however it was inferred
        return True

    def store_free(self, ctx: _Ctx, target) -> bool:
        """An attribute/item write that cannot be a write to a mapped row."""
        base = self.etype(ctx, target.value)
        if base is None:
            return False
        if base[0] in ("val", "extinst", "logger"):
            return True
        if base[0] == "inst":
            return not self._may_be_model_instance(base[1])
        return False

    def callable_ref_free(self, ctx: _Ctx, expr) -> bool:
        """A callable *reference* whose invocation is effect-free."""
        if isinstance(expr, ast.Lambda):
            return all(self.call_free(ctx, n) for n in ast.walk(expr.body) if isinstance(n, ast.Call))
        ident = self.identity(ctx, expr)
        if ident is None:
            return False
        kind, name = ident
        if kind == "builtin":
            return name in BUILTIN_VALUE_TYPES
        if kind == "func":
            module, node = self.toplevel_funcs[name]
            return self.function_free(module, node)
        if kind == "class":
            return self.class_ctor_free(name)
        if kind == "localfn":
            return True  # its body is part of the enclosing function, checked there
        return False

    def _kw_guard(self, ctx: _Ctx, call: ast.Call, allow_splat: bool = False) -> bool:
        """No callback smuggled in by keyword (or by an opaque ** splat)."""
        for kw in call.keywords:
            if kw.arg is None:
                if not allow_splat:
                    return False
            elif kw.arg in HIGHER_ORDER_KW and not isinstance(kw.value, ast.Constant):
                if not self.callable_ref_free(ctx, kw.value):
                    return False
        return True

    def call_free(self, ctx: _Ctx, call: ast.Call, tainted: frozenset = frozenset(),
                  dangerous: frozenset = frozenset()) -> bool:
        """True only when `call` provably cannot read or write a modeled table."""
        prev = self._extra_dangerous
        # Only this call site's names: nested classifications (other functions' bodies)
        # run through call_free again and install their own (empty) set.
        self._extra_dangerous = frozenset(tainted) | frozenset(dangerous)
        try:
            ok, external = self._call_free(ctx, call)
        finally:
            self._extra_dangerous = prev
        if ok and external and tainted:
            # A trusted first-order callable handed a live query object may iterate
            # (and thereby execute) it.
            # Names inside a nested call belong to that call, which is classified on
            # its own; only a query object passed directly (or inside a display) counts.
            todo = [*call.args, *(kw.value for kw in call.keywords)]
            while todo:
                node = todo.pop()
                if isinstance(node, ast.Call):
                    continue
                if isinstance(node, ast.Name) and node.id in tainted:
                    return False
                todo.extend(ast.iter_child_nodes(node))
        return ok

    def _callee(self, ctx: _Ctx, call: ast.Call):
        """The callee expression, seeing through `Cls[T](...)` generic parametrisation."""
        func = call.func
        if isinstance(func, ast.Subscript):
            ident = self.identity(ctx, func.value)
            if ident and ident[0] in ("class", "ext", "builtin"):
                return func.value
        return func

    def _dataclass_slot_store(self, ctx, call):
        """object.__setattr__(self, literal, value) writing a dataclass-generated slot."""
        if (not ctx.owner or ctx.fn.name != "__post_init__" or ctx.fn.decorator_list
                or len(call.args) != 3 or call.keywords
                or not isinstance(call.args[0], ast.Name) or call.args[0].id != ctx.self_name
                or self.etype(ctx, call.args[0]) != ("inst", ctx.owner)
                or not isinstance(call.args[1], ast.Constant) or not isinstance(call.args[1].value, str)
                or self._descendants(ctx.owner)):
            return False
        field = call.args[1].value
        module, cls = self.class_defs[ctx.owner]
        if field.startswith("__") or cls.bases or cls.keywords or len(cls.decorator_list) != 1:
            return False
        dec = cls.decorator_list[0]
        mctx = self.module_ctx(module)
        if (not isinstance(dec, ast.Call) or self.identity(mctx, dec.func) != ("ext", "dataclasses.dataclass")
                or not any(k.arg == "slots" and isinstance(k.value, ast.Constant) and k.value.value is True
                           for k in dec.keywords)):
            return False
        for item in cls.body:
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name) and item.target.id == field:
                ann = item.annotation.value if isinstance(item.annotation, ast.Subscript) else item.annotation
                ident = self.identity(mctx, ann)
                return bool(ident and ident[0] == "builtin" and ident[1] in BUILTIN_VALUE_TYPES)
        return False

    def _call_free(self, ctx: _Ctx, call: ast.Call) -> tuple[bool, bool]:
        func = self._callee(ctx, call)
        key, refused = self.declaration_for(ctx, call, self._extra_dangerous)
        if key and not refused:
            # Explicit user declaration (policy adapter.ignore_calls): NOT a proof.  The
            # id travels with the verdict through every cache and every caller.
            self._note({f"declared-free:{key}"})
            return True, False
        claim = self.assumption_for(ctx, call, "effects", self._extra_dangerous)
        if claim is not None and claim.claim == [] and self.irrelevance_refusal(
                ctx, call, claim.id, self._extra_dangerous) is None:
            # `effects: []` from the assumptions file: an assumption (or a reviewed fact),
            # recorded under its id wherever this verdict travels.
            self._note({claim.key})
            return True, False
        # No declaration, or a refused one: classify the call on its own merits.  A
        # refused declaration contributes nothing -- the oracle must prove it or not.
        ident = self.identity(ctx, func)
        if ident is not None:
            kind, name = ident
            if kind == "builtin":
                return self._builtin_free(ctx, name, call), True
            if kind == "ext":
                return self._ext_free(ctx, name, call), True
            if kind == "func":
                module, node = self.toplevel_funcs[name]
                return self.function_free(module, node), False
            if kind == "class":
                return self.class_ctor_free(name), False
            if kind == "localfn":
                return True, False
            return False, False
        if not isinstance(func, ast.Attribute):
            return False, False
        attr = func.attr
        # AnyIO's concrete Path wraps pathlib.Path; exists() dispatches that
        # path's filesystem probe in a worker thread. Keep the trust decision
        # local to this operation on a directly constructed receiver.
        if (attr == "exists" and not call.args and not call.keywords
                and isinstance(func.value, ast.Call)
                and self.identity(ctx, func.value.func) == ("ext", "anyio.Path")):
            return True, True
        if (isinstance(func.value, ast.Call) and not func.value.args and ctx.owner
                and self.identity(ctx, func.value.func) == ("builtin", "super")):
            # super().m(...): dispatches within the owner's hierarchy (siblings included)
            defs = self._method_defs(ctx.owner, attr)
            if defs is None:
                return False, False
            others = [d for d in defs if d[1] is not ctx.fn]
            if not all(self.function_free(module, node, cls) for module, node, cls in others):
                return False, False
            trusted_external = (CONSTRUCTION_METHODS | PYDANTIC_READONLY_METHODS
                                | PYDANTIC_CLASS_METHODS)
            return bool(others) or attr in trusted_external, False
        base_ident = self.identity(ctx, func.value)
        if base_ident == ("builtin", "object") and attr == "__setattr__":
            return self._dataclass_slot_store(ctx, call), True
        if base_ident and base_ident[0] == "class":
            return self._class_method_free(base_ident[1], attr), False
        if base_ident and base_ident[0] == "builtin" and base_ident[1] in BUILTIN_VALUE_TYPES:
            # unbound method of a builtin type: dict.fromkeys, str.join, bytes.fromhex
            return self._kw_guard(ctx, call), True
        base = self.etype(ctx, func.value)
        if base is None:
            return False, False
        if base == ("binary_file_reader",):
            return attr == "read" and not call.args and not call.keywords, True
        if base[0] == "val":
            if (base[1], attr) in VAL_HIGHER_ORDER_METHODS or not self._kw_guard(ctx, call):
                return False, True
            if self.exact_builtin(ctx, func.value):
                return True, True
            # A declared `dict`/`list`/... may hold a repository subclass (A1): every
            # override of this method in such a subclass must be effect-free too.
            for sub in self.subclasses.get(base[1], ()):
                for other in [sub, *self._descendants(sub)]:
                    for item in self._methods(other, attr):
                        if not self.function_free(self.class_defs[other][0], item,
                                                  self.class_defs[other][1].name):
                            return False, True
            return True, True
        if base[0] == "logger":
            return self._loggers_free() and self._kw_guard(ctx, call), True
        if base[0] == "sqlexpr":
            return self._kw_guard(ctx, call), True
        if base[0] == "extinst":
            if base[1] in ROUTER_TYPES:
                return False, True
            return self._kw_guard(ctx, call), True
        if base[0] == "inst":
            return self._inst_method_free(base[1], attr), False
        return False, False

    def _loggers_free(self) -> bool:
        """A log call runs every installed handler/filter/formatter.  If the repository
        defines one (a subclass of something in `logging`), all of its methods must be
        effect-free, otherwise logging itself may write to the database."""
        cached = self.__dict__.get("_loggers_free_cache")
        if cached is not None:
            self._note(cached[1])
            return cached[0]
        return self._loggers_free_compute()

    def _loggers_free_compute(self) -> bool:
        self._deps.append(set())
        ok = True
        roots = [base for base in self.subclasses if base.startswith(("logging.", "structlog."))]
        classes = set()
        for base in roots:
            for sub in self.subclasses[base]:
                classes |= {sub, *self._descendants(sub)}
        for cls in sorted(classes):
            module, node = self.class_defs[cls]
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not self.function_free(module, item, node.name):
                        ok = False
        deps = frozenset(self._deps.pop())
        if ok:
            self._note(deps)
        if not self._stack and not self._ctor_stack:
            self._loggers_free_cache = (ok, deps if ok else frozenset())
        return ok

    def _builtin_free(self, ctx: _Ctx, name: str, call: ast.Call) -> bool:
        if _is_exception_builtin(name):
            return True
        if name in ("setattr", "delattr"):
            if not call.args:
                return False
            base = self.etype(ctx, call.args[0])
            if base is None:
                return False
            if base[0] == "inst":
                return not self._may_be_model_instance(base[1])
            return base[0] in ("val", "extinst")
        if name not in FIRST_ORDER_BUILTINS:
            return False
        if name == "iter" and len(call.args) != 1:
            return False
        return self._kw_guard(ctx, call, allow_splat=name == "dict")

    def _ext_free(self, ctx: _Ctx, name: str, call: ast.Call) -> bool:
        if name in {"threading.Lock", "threading.RLock"}:
            return not call.args and not call.keywords
        if name == "anyio.Path":
            return not call.keywords and self._kw_guard(ctx, call)
        if name in ("asyncio.to_thread", "anyio.to_thread.run_sync"):
            return bool(call.args) and self.callable_ref_free(ctx, call.args[0]) and self._kw_guard(ctx, call)
        if name in EXT_NOT_FREE:
            if name in ("re.sub", "re.subn") and len(call.args) >= 2:
                return self.etype(ctx, call.args[1]) == ("val", "str") and self._kw_guard(ctx, call)
            return False
        if name == "collections.defaultdict":
            return not call.args or (
                isinstance(call.args[0], ast.Name)
                and self.identity(ctx, call.args[0]) in {("builtin", t) for t in BUILTIN_VALUE_TYPES})
        if (name in EXT_FREE_EXACT or name in EXT_VALUE_CLASSES or name in SQL_EXPR_FREE
                or name in LOGGER_FACTORIES
                or name.startswith(("sqlmodel.func.", "sqlalchemy.func.", "sqlalchemy.sql.func."))
                or name.startswith(EXT_FREE_MODULES)
                or any(name.startswith(obj + ".") for obj in LOGGER_OBJECTS)):
            return self._kw_guard(ctx, call)
        return False

    def _inst_method_free(self, q: str, attr: str) -> bool:
        defs = self._method_defs(q, attr)
        if defs is None:
            return False
        if defs:
            return all(self.function_free(module, node, cls) for module, node, cls in defs)
        # Not defined anywhere in the repository hierarchy: inherited from a trusted
        # external base (pydantic/enum/builtin).  Trust only read-only framework methods.
        if attr not in PYDANTIC_READONLY_METHODS:
            return False
        return all(self.class_ctor_free(cls) for cls in [q, *self._descendants(q)])

    def _class_method_free(self, q: str, attr: str) -> bool:
        defs = self._method_defs(q, attr)
        if defs is None:
            return False
        if defs:
            return all(self.function_free(module, node, cls) for module, node, cls in defs)
        if attr not in PYDANTIC_CLASS_METHODS:
            return False
        return all(self.class_ctor_free(cls) for cls in [q, *self._descendants(q)])

    # ---------------------------------------------------------------- dispatch
    def dispatch_targets(self, ctx: _Ctx, call: ast.Call):
        """Every repository definition `call` may dispatch to, as (module, node, class
        name), or None when the callee is not a statically identified repository
        function/method.  More than one entry means overriding definitions exist."""
        func = call.func
        ident = self.identity(ctx, func)
        if ident is not None:
            if ident[0] == "func":
                module, node = self.toplevel_funcs[ident[1]]
                return [(module, node, None)]
            return None
        if not isinstance(func, ast.Attribute):
            return None
        base_ident = self.identity(ctx, func.value)
        if base_ident and base_ident[0] == "class":
            return self._method_defs(base_ident[1], func.attr) or None
        base = self.etype(ctx, func.value)
        if base is not None and base[0] == "inst":
            return self._method_defs(base[1], func.attr) or None
        return None

    def receiver_is_class_object(self, ctx: _Ctx, call: ast.Call) -> bool:
        func = call.func
        if not isinstance(func, ast.Attribute):
            return False
        ident = self.identity(ctx, func.value)
        return bool(ident and ident[0] == "class")

    # -------------------------------------------------- policy declarations (binding)
    def binding_key(self, ctx: _Ctx, call: ast.Call, names) -> str | None:
        """The entry of `names` (policy ignore_calls / helpers keys) that names THIS call.

        A declaration binds by the callee's exact written spelling or by its resolved
        qualified identity.  A bare leaf name binds only to a callee the adapter cannot
        resolve to repository source (an unreadable receiver such as `vendor.emit`):
        it must never silently apply to an unrelated same-named repository function."""
        if not names:
            return None
        func = self._callee(ctx, call)
        spelling = dotted(func)
        if spelling and spelling in names:
            return spelling
        ident = self.identity(ctx, func)
        qualified = ident[1] if ident and ident[0] in ("func", "class", "ext", "global") else None
        if qualified and qualified in names:
            return qualified
        leaf = spelling.split(".")[-1] if spelling else (
            func.attr if isinstance(func, ast.Attribute) else None)
        if not leaf or leaf not in names:
            return None
        in_repo = bool(ident and ident[0] in ("func", "class", "localfn")) or bool(
            self.dispatch_targets(ctx, call))
        return None if in_repo else leaf

    def _db_like_names(self, ctx: _Ctx) -> set[str]:
        """Parameters of the enclosing function that hold a database handle."""
        fn = ctx.fn
        if fn is None or not hasattr(fn, "args"):
            return set()
        out = set()
        a = fn.args
        for arg in [*a.posonlyargs, *a.args, *a.kwonlyargs]:
            ann = (dotted(arg.annotation) or "").lower() if arg.annotation is not None else ""
            if arg.arg in {"db", "session"} or "session" in ann:
                out.add(arg.arg)
        return out

    def declaration_for(self, ctx: _Ctx, call: ast.Call, dangerous=frozenset()):
        """(key, refusal) for the policy `adapter.ignore_calls` declaration naming `call`.

        (None, None)  no declaration names this call.
        (key, None)   the declaration applies: the call may be treated as data-irrelevant
                      (recorded as an assumption by the caller, never as a proof).
        (key, why)    a declaration names it but is REFUSED; the call must then be
                      classified on its own merits, exactly as if undeclared.

        A declaration may only suppress what the adapter cannot otherwise see, and only
        when the call cannot reach the database through what it is handed:
          2c  refuted if the callee resolves to repository code that visibly reads or
              writes the database;
          2a  refused if the call is handed a db/session handle, a live query, a tracked
              row, a model class or a callable, or is a method on such a receiver."""
        key = self.binding_key(ctx, call, self.declared_free)
        if key is None:
            return None, None
        return key, self.irrelevance_refusal(ctx, call, key, dangerous)

    # ---------------------------------------------------------------- assumptions file
    def call_symbol(self, ctx: _Ctx, call: ast.Call) -> str | None:
        """Resolved identity of the callee: a qualified function/class/external name, or
        `<qualified class>.<method>` for a method on a receiver of known class.  None when
        the callee has no static identity (it can then only be named as a `site`)."""
        func = self._callee(ctx, call)
        ident = self.identity(ctx, func)
        if ident is not None:
            return ident[1] if ident[0] in ("func", "class", "ext", "global") else None
        if isinstance(func, ast.Attribute):
            base_ident = self.identity(ctx, func.value)
            if base_ident and base_ident[0] == "class":
                return f"{base_ident[1]}.{func.attr}"
            base = self.etype(ctx, func.value)
            if base is not None and base[0] == "inst":
                return f"{base[1]}.{func.attr}"
        return None

    @staticmethod
    def enclosing_symbol(ctx: _Ctx) -> str | None:
        if ctx.fn is None:
            return None
        return f"{ctx.owner or ctx.module}.{ctx.fn.name}"

    def call_target(self, ctx: _Ctx, call: ast.Call) -> str:
        """What an assumption has to name to cover this call."""
        return self.call_symbol(ctx, call) or (
            f"{self.enclosing_symbol(ctx)} :: {ast.unparse(call.func)}")

    def _kernel_call(self, ctx: _Ctx, call: ast.Call, dangerous=frozenset()) -> bool:
        """The database kernel is adapter semantics: no assumption ever applies to a call
        on a session/db/query receiver or to a statement constructor."""
        func = self._callee(ctx, call)
        ident = self.identity(ctx, func)
        if ident and ident[0] == "ext" and ident[1].split(".")[0] in ("sqlalchemy", "sqlmodel"):
            return True
        if isinstance(func, ast.Attribute):
            recv = dotted(func.value)
            bad = set(dangerous) | self._db_like_names(ctx) | {"db", "session"}
            if recv and (recv in bad or recv.split(".")[0] in bad
                         or recv.split(".")[-1] in ("db", "session")):
                return True
        return False

    def assumption_for(self, ctx: _Ctx, call: ast.Call, kind: str, dangerous=frozenset()):
        """The entry of the assumptions file that makes a `kind` claim about THIS call, or
        None.  Binding is by exact call site or by the callee's resolved identity; an
        unresolvable target, a short name or another module's namesake never binds."""
        entries = self.assumptions
        if not entries or ctx is None:
            return None
        entry = None
        if entries.by_site and ctx.fn is not None:
            entry = entries.by_site.get(
                (self.enclosing_symbol(ctx), ast.unparse(call.func)), {}).get(kind)
        if entry is None and entries.by_symbol:
            symbol = self.call_symbol(ctx, call)
            if symbol is not None:
                entry = entries.by_symbol.get(symbol, {}).get(kind)
        if entry is None or entry.status == "unbound":
            return None
        if self._kernel_call(ctx, call, dangerous):
            return None
        return entry

    def irrelevance_refusal(self, ctx: _Ctx, call: ast.Call, key: str, dangerous=frozenset()):
        """Why a "this call touches no data" claim must NOT apply at this call site, or
        None when it may.  Shared by policy ignore_calls and `effects: []` assumptions."""
        for module, node, cls in (self.dispatch_targets(ctx, call) or []):
            ref = SimpleNamespace(module=module, node=node, file="",
                                  owner_class=cls.rsplit(".", 1)[-1] if cls else None)
            if self.index.function_may_touch_db(ref):
                return f"{key} is declared data-irrelevant but visibly reads or writes the database"
        bad = set(dangerous) | self._db_like_names(ctx)
        func = self._callee(ctx, call)
        if isinstance(func, ast.Attribute):
            recv = dotted(func.value)
            if recv and (recv in bad or recv.split(".")[0] in bad):
                return f"{key} is called on a database handle, live query or tracked row"
        for kw in call.keywords:
            if kw.arg in HIGHER_ORDER_KW and not isinstance(kw.value, ast.Constant):
                return f"{key} is handed a callback ({kw.arg}=)"
        for value in [*call.args, *(kw.value for kw in call.keywords)]:
            for node in ast.walk(value):
                if isinstance(node, ast.Lambda):
                    return f"{key} is handed a callable"
                if not isinstance(node, ast.Name):
                    continue
                if node.id in bad:
                    return f"{key} is handed {node.id} (a database handle, live query or tracked row)"
                if node.id in self.models:
                    return f"{key} is handed the model class {node.id}"
                ident = self.identity(ctx, node)
                if ident and ident[0] in ("func", "localfn"):
                    return f"{key} is handed a callable ({node.id})"
        return None
