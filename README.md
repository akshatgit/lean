# keyhole

A static analyzer for IDOR (object-level authorization) bugs in web APIs. For each endpoint it reports one of:

- **SAFE**: a checker *proven correct in Lean 4* showed every object the endpoint reads or changes is allowed by your policy.
- **SAFE (assumed)**: the Lean proof depends on an unconfirmed policy or trusted helper summary.
- **POSSIBLE VIOLATION**: Lean found a counterexample, but an earlier opaque helper may reject or filter the request.
- **VIOLATION**: a concrete counterexample, also checked by the Lean semantics, with a request to reproduce it.
- **UNKNOWN**: code the adapter could not model. Never silently treated as safe.

The engine, AIR, Lean checker, policy language, and reports are framework-neutral. Source support is
provided by adapters; FastAPI + SQLAlchemy is the built-in adapter, and third-party adapters can be
registered through the `keyhole.adapters` entry-point group.

## Quick start

```bash
# 1. Build the verified checker (Lean 4.24)
cd core && lake build && cd ..

# 2. Install the Python side
pip install -e '.[dev]'

# 3. Scan the demo app
keyhole scan examples/docs_app
keyhole explain examples/docs_app "GET /api/v1/documents/{doc_id}"
keyhole scan examples/docs_app --format sarif --out keyhole.sarif
keyhole scan examples/docs_app --format html --out keyhole-report.html --stats keyhole-stats.json
keyhole validate-policy examples/docs_app/keyhole.policy.yaml
pytest
```

The scanner also has a self-contained container image. Mount the target repository read-only and
mount a separate output directory writable:

```bash
docker build -t keyhole .
docker run --rm \
  -v /path/to/target:/target:ro \
  -v /path/to/output:/output \
  keyhole scan /target \
  --policy /output/generated.policy.yaml \
  --format html --out /output/keyhole-report.html \
  --stats /output/keyhole-stats.json
```

Expected output on the demo:

```
VIOLATION       GET /api/v1/documents/{doc_id}   (app.py:38)
    caller (id=<v3>) can read a Document row (id=<v0>, owner_id=<v2>, visibility=<v4>)
    repro: as that caller, GET /api/v1/documents/<v0>
SAFE            GET /api/v2/documents/{doc_id}   (app.py:46)
...
10 endpoints: 5 SAFE, 0 SAFE (assumed), 4 VIOLATION, 1 UNKNOWN
```

`scan` exits with status 1 when there is a violation, so it can gate CI.
Use `--fail-on possible` to also fail on possible violations. Test modules are
excluded by default; pass `--include-tests` to analyze them. `--stats PATH` writes
JSON verdict counts and UNKNOWN-cause histograms alongside the normal report.

The HTML format is a self-contained, human-readable report. It explains each
verdict and lets you filter by result, resource, review status, endpoint, or
source file without a server or external assets.

If multiple handlers share a method and route, `explain` lists their locations.
Pass `--source FILE:LINE` using the location from the report. For a complete AIR
snapshot, pass an empty directory to `scan --air-dir DIR`. Routes with colliding
filenames get numbered suffixes, and every JSON record includes its route and source.

## How it works

```
1  source repo
2a parse code (adapter, deterministic)      keyhole/adapters/fastapi_sqla.py
2b analyze repo helpers (depth 3), then use any committed summaries for gaps
3  AIR (Authorization Intermediate Representation), JSON
4-5 policy (keyhole.policy.yaml, human-confirmed)   keyhole/policy.py
6  Lean checker                              core/Keyhole/Check.lean -> keyhole-core
7  report: text, JSON, SARIF, HTML, stats    keyhole/report.py
```

### What is proven (core/Keyhole/Check.lean)

```lean
theorem check_sound   : check e pol = .safe → Safe e pol
theorem check_witness : check e pol = .violation w →
    e.touches w.toEnv = true ∧ (pol.rule e.resource e.kind).eval w.toEnv = false
```

`Safe e pol` means: for *every* request and row, if the effect can touch the row (guards and selector hold), the policy allows it. The checker puts both sides in DNF and checks entailment with equality reasoning (proven sound once). A candidate counterexample is reported only after the Lean evaluator confirms it. No `sorry`; the proofs use only the standard axioms (`propext`, `Quot.sound`).

### What is *not* proven

The guarantee covers the AIR, not your Python. The adapter is trusted and must
over-approximate what source can touch. Unsupported database-relevant calls
become `opaque`; unsupported checks and query conditions are dropped from the
AIR and shown as notes, which is conservative but may cause false alarms.
Helper summaries and configured helper guarantees are trusted input; results
that depend on an unreviewed one are labelled `assumes:`. Policies not marked
`confirmed: true` downgrade SAFE to SAFE (assumed). Keyhole does not invoke an
LLM during a scan.

## Policy

```yaml
principal:
  id: current_user.id
  bypass: current_user.is_superuser      # optional
  dependencies: [get_current_active_user] # optional dependency names
  types: [CurrentActiveUser]              # optional Annotated aliases
helpers:
  ensure_document_access: owner(owner_id) # trusted; reported as assumed
adapter:
  ignore_calls: [metrics.increment]        # project-specific non-DB calls
resources:
  Document:
    confirmed: true
    read:   owner(owner_id) or visibility == 'public'
    update: owner(owner_id)
    delete: owner(owner_id)
    create: owner(owner_id)              # blocks setting someone else's owner_id
```

A missing kind means deny.

Policy generation is deliberately out of process. A person or any external model can author the
same YAML; machine-generated resources must stay `confirmed: false`, which limits successful proofs
to SAFE (assumed). See [`docs/POLICY_GENERATION.md`](docs/POLICY_GENERATION.md) for the provider-neutral
generation contract and reproducible report workflow.

The checked-in Langflow evaluation is an example, not application-specific engine behavior. Its
read-only Claude-generated policy is [`langflow-keyhole.claude.policy.yaml`](langflow-keyhole.claude.policy.yaml),
the human-readable result is [`langflow-claude-policy-docker-report.html`](langflow-claude-policy-docker-report.html),
and the assumptions/counts/manual triage are documented in
[`langflow-claude-policy-triage.md`](langflow-claude-policy-triage.md).

For resources where an unowned row is shared, use
`owner(owner_id) or is_null(owner_id)`. The latter matches a null field value.
Quoted strings such as `'None'` are ordinary string values.

## Supported FastAPI/SQLAlchemy patterns (MVP)

| Pattern | Example |
| --- | --- |
| Routes | `@router.get("/documents/{doc_id}")` with `APIRouter(prefix=...)` |
| Test exclusion | Skips `tests/`, `test_*.py`, `*_test.py`, and `conftest.py`; `--include-tests` opts in |
| Principal | `Depends`/`Security`, cross-module aliases, policy-declared names, and recognized app/router/include-router dependencies |
| Reads | `db.get`, legacy queries, `exec`/`execute`/`scalar(s)`, and incrementally built `stmt = stmt.where(...)` queries |
| Conditions | Equality, `and`/`or`, `&`/`\|`, and `col(Model.field)`; unsupported filters are dropped conservatively |
| Writes | `obj.attr = v` (update), `db.delete(obj)`, `M(...)` + `db.add(obj)` (create), `query(...).delete()` |
| Guards | Path-aware `if`/`else`, returns, loops, and conservative `try`/`except` merging; unsupported checks become possible-violation blockers |
| Calls | Receiver-aware container/logging/response/Pydantic allowlists; unresolved result flow into responses, selectors, mutations, or control becomes opaque |
| Helpers | Repo functions are analyzed across imports to depth 3, including returned rows and parameter-row guards; recursion is opaque |
| Trusted authorization | Policy `helpers:` rules add explicit assumed guards and can only produce SAFE (assumed) |

## Not yet implemented

- `keyhole init` policy inference and `keyhole summarize`; policy generation remains external by design, while `validate-policy` checks its schema and expressions.
- Membership joins in adapters (the policy language and Lean core already support `member`).
- `keyhole confirm` dynamic replay, `--diff` mode, more frameworks (Express, Django).

## Citation

Use GitHub's **Cite this repository** link to generate a citation in BibTeX
or APA format. The citation metadata lives in [`CITATION.cff`](CITATION.cff);
include the release version or commit you analyzed so results remain
reproducible.
