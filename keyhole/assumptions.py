"""Assumptions file (`keyhole.assumptions.yaml`): the second human-controlled surface.

The policy says what SHOULD be allowed.  An assumption states a fact about code the
adapter cannot establish by itself.  Every assumption is

  * bound to ONE target by resolved identity (never a short name),
  * exactly ONE claim,
  * fingerprinted against the target it was written for,
  * unreviewed until a human runs `keyhole review`, which records digests over the claim
    and the target.  A later edit of either silently un-reviews it.

    schema: 1
    assumptions:
      - id: A-0007
        target:
          symbol: pkg.services.deps.get_settings_service
          # or:  site: {function: pkg.mod.handler, callee: "self._services[name].run"}
          # params: [a, b]        # positional formals, only for targets outside the repo
        fingerprint: {kind: repo-ast, sha256: "..."}      # optional; what it was drafted against
        claim:                                             # exactly one key
          returns_type: pkg.services.settings.SettingsService
          # effects: []                                    # exhaustive; [] = no mapped table
          # effects: [{kind: create, resource: AuditLog, selector: true}]
          # ensures: {row: {param: flow}, guard: {eq: [{field: user_id}, {param_attr: [user, id]}]}}
          #          (`row`, not `on`: YAML 1.1 reads a bare `on` key as the boolean true)
          # principal: true
        evidence: {file: "...", lines: [10, 42], quote: "..."}
        drafted_by: {tool: "...", at: "..."}
        review: {by: "...", at: "...", entry_sha256: "...", target_sha256: "..."}

Claim predicates use AIR's shape with two extra terms that refer to the target's formals:
  {param: NAME}             the actual argument bound to formal NAME
  {param_attr: [NAME, A]}   attribute A of the actual bound to NAME, usable only when
                            that actual is the endpoint's principal
"""
from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

SCHEMA_VERSION = 1
# Bumped whenever the adapter changes what a claim MEANS; part of every digest, so an
# engine change re-opens every review.
SEMANTICS_VERSION = "2026.11-a"

CLAIM_KINDS = ("returns_type", "effects", "ensures", "principal")
EFFECT_KINDS = ("read", "update", "delete", "create")

_ENTRY_KEYS = {"id", "target", "fingerprint", "claim", "evidence", "drafted_by", "review"}
_TARGET_KEYS = {"symbol", "site", "params"}
_SITE_KEYS = {"function", "callee"}
_FINGERPRINT_KEYS = {"kind", "sha256", "name", "version", "source_sha256"}
_REVIEW_KEYS = {"by", "at", "entry_sha256", "target_sha256"}
_EVIDENCE_KEYS = {"file", "lines", "quote", "note"}
_DRAFT_KEYS = {"tool", "at", "model", "note"}

# The database kernel is adapter semantics, never an assumption: nobody may declare
# what `session.exec` or `select` "really" does.
_KERNEL_MODULES = ("sqlalchemy", "sqlmodel")
_KERNEL_RECEIVERS = {"db", "session", "conn", "connection", "engine"}
_KERNEL_CALLEES = {"select", "insert", "update", "delete", "text", "exists", "union", "union_all"}
_KERNEL_METHODS = {"exec", "execute", "scalars", "scalar", "get", "add", "add_all", "merge",
                   "delete", "flush", "commit", "rollback", "refresh", "query", "begin",
                   "begin_nested", "expire", "expunge", "close", "stream", "run_sync"}


class AssumptionError(ValueError):
    pass


def _fail(entry_id, message):
    raise AssumptionError(f"assumption {entry_id or '<no id>'}: {message}")


def _only_keys(entry_id, what, mapping, allowed):
    if not isinstance(mapping, dict):
        _fail(entry_id, f"{what} must be a mapping")
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        _fail(entry_id, f"unknown key(s) in {what}: {', '.join(map(str, unknown))}")


def _sha(payload) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode()).hexdigest()


@dataclass
class Assumption:
    id: str
    symbol: str | None
    site: tuple | None            # (function, callee text)
    params: list | None
    kind: str                     # one of CLAIM_KINDS
    claim: object
    fingerprint: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)
    drafted_by: dict = field(default_factory=dict)
    review: dict | None = None
    # computed by AssumptionSet.resolve
    status: str = "assumed"       # reviewed | assumed | stale | unbound
    reason: str = "not reviewed"
    entry_sha256: str = ""
    target_sha256: str | None = None
    target_kind: str = "unresolved"

    @property
    def key(self) -> str:
        """Provenance id recorded on every endpoint whose model used this entry."""
        return f"{'reviewed' if self.status == 'reviewed' else 'assume'}:{self.id}"

    @property
    def target_text(self) -> str:
        return self.symbol or f"{self.site[0]} :: {self.site[1]}"

    def describe(self) -> str:
        return f"assumption {self.id} ({self.kind} of {self.target_text}): {self.reason}"

    def entry_digest(self) -> str:
        return _sha({"schema": SCHEMA_VERSION, "semantics": SEMANTICS_VERSION,
                     "target": {"symbol": self.symbol, "site": list(self.site) if self.site else None,
                                "params": self.params},
                     "claim": {self.kind: self.claim}})


# ----------------------------------------------------------------------------- loading

def _check_pred(entry_id, pred, where):
    if pred is True or pred is False:
        return
    if not isinstance(pred, dict) or len(pred) != 1:
        _fail(entry_id, f"{where}: a predicate is true/false or a one-key mapping")
    (kind, value), = pred.items()
    if kind in ("and", "or"):
        if not isinstance(value, list) or not value:
            _fail(entry_id, f"{where}: {kind} needs a non-empty list")
        for part in value:
            _check_pred(entry_id, part, where)
    elif kind == "eq":
        if not isinstance(value, list) or len(value) != 2:
            _fail(entry_id, f"{where}: eq needs exactly two terms")
        for term in value:
            _check_term(entry_id, term, where)
    else:
        _fail(entry_id, f"{where}: unknown predicate {kind!r}")


def _check_term(entry_id, term, where):
    if not isinstance(term, dict) or len(term) != 1:
        _fail(entry_id, f"{where}: a term is a one-key mapping")
    (kind, value), = term.items()
    if kind in ("field", "param", "const"):
        if kind != "const" and not isinstance(value, str):
            _fail(entry_id, f"{where}: {kind} takes a name")
    elif kind == "param_attr":
        if not (isinstance(value, list) and len(value) == 2 and all(isinstance(v, str) for v in value)):
            _fail(entry_id, f"{where}: param_attr takes [formal, attribute]")
    else:
        _fail(entry_id, f"{where}: unknown term {kind!r}")


def _check_kernel(entry_id, symbol, site):
    if symbol:
        parts = symbol.split(".")
        if parts[0] in _KERNEL_MODULES:
            _fail(entry_id, f"target {symbol} is part of the database kernel; it cannot be assumed")
        if parts[-1] in _KERNEL_CALLEES and len(parts) <= 2:
            _fail(entry_id, f"target {symbol} is a statement constructor; it cannot be assumed")
        if len(parts) >= 2 and parts[-2] in _KERNEL_RECEIVERS | {"Session", "AsyncSession"} \
                and parts[-1] in _KERNEL_METHODS:
            _fail(entry_id, f"target {symbol} is a session method; it cannot be assumed")
    if site:
        callee = site[1].replace(" ", "")
        try:
            node = ast.parse(callee, mode="eval").body
        except SyntaxError:
            _fail(entry_id, f"site callee {site[1]!r} is not an expression")
        names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
        attrs = {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}
        leaf = node.attr if isinstance(node, ast.Attribute) else (node.id if isinstance(node, ast.Name) else "")
        if (names | attrs) & _KERNEL_RECEIVERS or leaf in _KERNEL_CALLEES:
            _fail(entry_id, f"site callee {site[1]!r} is a database handle or statement "
                            f"constructor; it cannot be assumed")


def parse_entry(raw) -> Assumption:
    if not isinstance(raw, dict):
        raise AssumptionError("each assumption must be a mapping")
    entry_id = raw.get("id")
    if not isinstance(entry_id, str) or not entry_id.strip():
        _fail(None, "missing id")
    _only_keys(entry_id, "the entry", raw, _ENTRY_KEYS)

    target = raw.get("target")
    _only_keys(entry_id, "target", target, _TARGET_KEYS)
    symbol, site = target.get("symbol"), target.get("site")
    if (symbol is None) == (site is None):
        _fail(entry_id, "target needs exactly one of symbol / site")
    if symbol is not None:
        if not isinstance(symbol, str) or "." not in symbol or symbol.startswith(".") or " " in symbol:
            _fail(entry_id, f"target.symbol must be a fully qualified dotted name, got {symbol!r}")
    else:
        _only_keys(entry_id, "target.site", site, _SITE_KEYS)
        if set(site) != _SITE_KEYS or not all(isinstance(v, str) and v for v in site.values()):
            _fail(entry_id, "target.site needs function and callee")
        if "." not in site["function"]:
            _fail(entry_id, "target.site.function must be fully qualified")
        site = (site["function"], site["callee"])
    params = target.get("params")
    if params is not None and not (isinstance(params, list) and all(isinstance(p, str) for p in params)):
        _fail(entry_id, "target.params must be a list of formal names")
    _check_kernel(entry_id, symbol, site)

    claim = raw.get("claim")
    if not isinstance(claim, dict) or len(claim) != 1:
        _fail(entry_id, "claim must hold exactly one claim")
    (kind, payload), = claim.items()
    if kind not in CLAIM_KINDS:
        _fail(entry_id, f"unknown claim kind {kind!r}")
    if kind == "returns_type":
        if not isinstance(payload, str) or "." not in payload:
            _fail(entry_id, "returns_type must be a fully qualified class name")
    elif kind == "effects":
        if not isinstance(payload, list):
            _fail(entry_id, "effects must be a list (use [] for no mapped table)")
        for item in payload:
            _only_keys(entry_id, "an effect", item, {"kind", "resource", "selector"})
            if item.get("kind") not in EFFECT_KINDS:
                _fail(entry_id, f"effect kind must be one of {', '.join(EFFECT_KINDS)}")
            if not isinstance(item.get("resource"), str):
                _fail(entry_id, "effect needs a resource")
            _check_pred(entry_id, item.get("selector", True), "effect selector")
    elif kind == "ensures":
        if isinstance(payload, dict) and True in payload:
            _fail(entry_id, "ensures: use `row:` for the guarded row (YAML reads a bare `on:` as true)")
        _only_keys(entry_id, "ensures", payload, {"row", "guard"})
        on = payload.get("row")
        if not (isinstance(on, dict) and set(on) == {"param"} and isinstance(on["param"], str)):
            _fail(entry_id, "ensures.row must be {param: FORMAL}")
        if "guard" not in payload or payload["guard"] in (True, False):
            _fail(entry_id, "ensures needs a guard predicate")
        _check_pred(entry_id, payload["guard"], "ensures guard")
    elif kind == "principal":
        if payload is not True:
            _fail(entry_id, "principal must be true")

    fingerprint = raw.get("fingerprint") or {}
    _only_keys(entry_id, "fingerprint", fingerprint, _FINGERPRINT_KEYS)
    evidence = raw.get("evidence") or {}
    _only_keys(entry_id, "evidence", evidence, _EVIDENCE_KEYS)
    drafted_by = raw.get("drafted_by") or {}
    _only_keys(entry_id, "drafted_by", drafted_by, _DRAFT_KEYS)
    review = raw.get("review")
    if review is not None:
        _only_keys(entry_id, "review", review, _REVIEW_KEYS)
        if not all(isinstance(review.get(k), str) and review.get(k) for k in ("by", "entry_sha256", "target_sha256")):
            _fail(entry_id, "review needs by, entry_sha256 and target_sha256")
    return Assumption(entry_id, symbol, site, params, kind, payload, dict(fingerprint),
                      dict(evidence), dict(drafted_by), dict(review) if review else None)


class AssumptionSet:
    def __init__(self, entries=(), path: Path | None = None):
        self.entries: list[Assumption] = list(entries)
        self.path = path
        self.by_symbol: dict[str, dict[str, Assumption]] = {}
        self.by_site: dict[tuple, dict[str, Assumption]] = {}
        ids = set()
        for entry in self.entries:
            if entry.id in ids:
                raise AssumptionError(f"duplicate assumption id {entry.id}")
            ids.add(entry.id)
            table = self.by_symbol.setdefault(entry.symbol, {}) if entry.symbol else \
                self.by_site.setdefault(entry.site, {})
            if entry.kind in table:
                _fail(entry.id, f"a second {entry.kind} claim for {entry.target_text} "
                                f"(already {table[entry.kind].id})")
            table[entry.kind] = entry
        self.resolved = False

    def __bool__(self):
        return bool(self.entries)

    def get(self, entry_id: str) -> Assumption | None:
        return next((e for e in self.entries if e.id == entry_id), None)

    # ------------------------------------------------------------------ fingerprints
    def resolve(self, purity):
        """Recompute every digest against the scanned repository and decide each entry's
        standing.  Called once, after the repository index exists."""
        for entry in self.entries:
            entry.entry_sha256 = entry.entry_digest()
            entry.target_kind, entry.target_sha256 = fingerprint_target(purity, entry)
            if entry.target_sha256 is None:
                entry.status = "unbound"
                entry.reason = (f"target does not resolve to anything in the scanned repository "
                                f"or environment ({entry.target_kind}); it never applies")
                continue
            entry.status, entry.reason = "assumed", "not reviewed"
            drafted = entry.fingerprint.get("sha256")
            if drafted and drafted != entry.target_sha256:
                entry.status = "stale"
                entry.reason = (f"stale: target changed since it was drafted "
                                f"({drafted[:12]} -> {entry.target_sha256[:12]})")
            review = entry.review
            if review:
                if review["entry_sha256"] != entry.entry_sha256:
                    entry.status = "assumed"
                    entry.reason = (f"claim edited after review ({review['entry_sha256'][:12]} -> "
                                    f"{entry.entry_sha256[:12]}); review no longer applies")
                elif review["target_sha256"] != entry.target_sha256:
                    entry.status = "stale"
                    entry.reason = (f"stale: target changed after review ({review['target_sha256'][:12]} "
                                    f"-> {entry.target_sha256[:12]}); review no longer applies")
                else:
                    entry.status = "reviewed"
                    entry.reason = f"reviewed by {review['by']}"
        self.resolved = True


def canonical_dump(node) -> str:
    """Position-free, docstring-free rendering of a definition (its decorators included)."""
    node = ast.parse(ast.unparse(node)).body[0]   # private copy; drops comments/positions
    for sub in ast.walk(node):
        body = getattr(sub, "body", None)
        if (isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and body
                and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            sub.body = body[1:] or [ast.Pass()]
    return ast.dump(node, annotate_fields=True, include_attributes=False)


def target_definitions(purity, symbol: str):
    """Every repository definition `symbol` denotes: a function, a class (whole body), or
    a method together with every override reachable through the class hierarchy.
    None when the symbol is not repository source."""
    if symbol in purity.toplevel_funcs:
        return [purity.toplevel_funcs[symbol][1]]
    if symbol in purity.class_defs:
        return [purity.class_defs[symbol][1]]
    owner, _, method = symbol.rpartition(".")
    if owner in purity.class_defs:
        defs = purity._method_defs(owner, method)
        if defs:
            return [node for _module, node, _cls in defs]
    return None


def fingerprint_target(purity, entry: Assumption):
    """(kind, sha256 | None).  None means the target cannot be found, so the entry can
    neither apply nor be reviewed."""
    header = {"schema": SCHEMA_VERSION, "semantics": SEMANTICS_VERSION}
    if entry.site:
        function = entry.site[0]
        defs = target_definitions(purity, function)
        if not defs:
            return "site: enclosing function not found", None
        return "site", _sha({**header, "kind": "site", "callee": entry.site[1],
                             "function": sorted(canonical_dump(d) for d in defs)})
    defs = target_definitions(purity, entry.symbol)
    if defs:
        return "repo-ast", _sha({**header, "kind": "repo-ast",
                                 "defs": sorted(canonical_dump(d) for d in defs)})
    top = entry.symbol.split(".")[0]
    if top in purity.repo_tops:
        return "repository symbol not found", None
    return _dist_fingerprint(header, entry.symbol)


def _dist_fingerprint(header, symbol: str):
    """An external target: identified by its distribution name and version, plus a hash of
    the defining module's source when that file can be read.  Nothing is imported."""
    from importlib import metadata

    top = symbol.split(".")[0]
    try:
        names = metadata.packages_distributions().get(top) or []
    except Exception:  # noqa: BLE001 - metadata backends vary
        names = []
    if not names:
        # Standard-library or not installed here: bind by name only.  Such an entry
        # can apply but its review is pinned to nothing more than the symbol itself.
        return "external", _sha({**header, "kind": "external", "symbol": symbol})
    name = sorted(names)[0]
    version = metadata.version(name)
    source_sha = None
    module_path = "/".join(symbol.split(".")[:-1]) + ".py"
    try:
        for item in metadata.files(name) or []:
            if str(item).endswith(module_path):
                text = Path(item.locate()).read_text(errors="ignore")
                ast.parse(text)
                source_sha = hashlib.sha256(text.encode()).hexdigest()
                break
    except (OSError, SyntaxError):
        source_sha = None
    return "dist", _sha({**header, "kind": "dist", "name": name, "version": version,
                         "source_sha256": source_sha, "symbol": symbol})


def load_assumptions(path: str | Path | None) -> AssumptionSet:
    if path is None:
        return AssumptionSet()
    path = Path(path)
    data = yaml.safe_load(path.read_text())
    if data is None:
        return AssumptionSet(path=path)
    if not isinstance(data, dict):
        raise AssumptionError("assumptions file must be a mapping")
    unknown = sorted(set(data) - {"schema", "assumptions"})
    if unknown:
        raise AssumptionError(f"unknown top-level key(s): {', '.join(unknown)}")
    if data.get("schema") != SCHEMA_VERSION:
        raise AssumptionError(f"unsupported schema {data.get('schema')!r}; this build reads {SCHEMA_VERSION}")
    raw = data.get("assumptions") or []
    if not isinstance(raw, list):
        raise AssumptionError("assumptions must be a list")
    return AssumptionSet([parse_entry(item) for item in raw], path=path)


def write_review(path: Path, entry: Assumption, reviewer: str, when: str):
    """Record a human review: digests over the claim as written and the target as it is."""
    data = yaml.safe_load(Path(path).read_text())
    for raw in data["assumptions"]:
        if raw.get("id") == entry.id:
            raw["review"] = {"by": reviewer, "at": when,
                             "entry_sha256": entry.entry_sha256, "target_sha256": entry.target_sha256}
            raw.setdefault("fingerprint", {})
            raw["fingerprint"] = {"kind": entry.target_kind, "sha256": entry.target_sha256}
            break
    else:
        raise AssumptionError(f"no assumption {entry.id} in {path}")
    Path(path).write_text(yaml.safe_dump(data, sort_keys=False, width=100))
