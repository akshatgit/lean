# keyhole

A static analyzer for IDOR (object-level authorization) bugs in web APIs. For each endpoint it reports one of:

- **SAFE**: a checker *proven correct in Lean 4* showed every object the endpoint reads or changes is allowed by your policy.
- **VIOLATION**: a concrete counterexample, also checked by the Lean semantics, with a request to reproduce it.
- **UNKNOWN**: code the adapter could not model. Never silently treated as safe.

This is the end-to-end MVP of the design doc: the Lean core, a FastAPI + SQLAlchemy adapter, the CLI, and a demo app.

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
pytest
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

## How it works

```
1  source repo
2a parse code (adapter, deterministic)      keyhole/adapters/fastapi_sqla.py
2b fill gaps with committed helper summaries keyhole/summaries.py, .keyhole/summaries/*.yaml
3  AIR (Authorization Intermediate Representation), JSON
4-5 policy (keyhole.policy.yaml, human-confirmed)   keyhole/policy.py
6  Lean checker                              core/Keyhole/Check.lean -> keyhole-core
7  report: text, JSON, SARIF                 keyhole/report.py
```

### What is proven (core/Keyhole/Check.lean)

```lean
theorem check_sound   : check e pol = .safe → Safe e pol
theorem check_witness : check e pol = .violation w →
    e.touches w.toEnv = true ∧ (pol.rule e.resource e.kind).eval w.toEnv = false
```

`Safe e pol` means: for *every* request and row, if the effect can touch the row (guards and selector hold), the policy allows it. The checker puts both sides in DNF and checks entailment with equality reasoning (proven sound once). A candidate counterexample is reported only after the Lean evaluator confirms it. No `sorry`; the proofs use only the standard axioms (`propext`, `Quot.sound`).

### What is *not* proven

The guarantee covers the AIR, not your Python. The adapter is trusted and conservative: unsupported patterns become `opaque` and the endpoint is UNKNOWN. Helper summaries (step 2b) are trusted input too; violations or safety that depend on one are labelled `assumes:` until the summary's `status` is `reviewed`. Policies not marked `confirmed: true` downgrade SAFE to SAFE (assumed).

## Policy

```yaml
principal:
  id: current_user.id
  bypass: current_user.is_superuser      # optional
resources:
  Document:
    confirmed: true
    read:   owner(owner_id) or visibility == 'public'
    update: owner(owner_id)
    delete: owner(owner_id)
    create: owner(owner_id)              # blocks setting someone else's owner_id
```

A missing kind means deny.

## Supported FastAPI/SQLAlchemy patterns (MVP)

| Pattern | Example |
| --- | --- |
| Routes | `@router.get("/documents/{doc_id}")` with `APIRouter(prefix=...)` |
| Principal | `user: User = Depends(get_current_user)` |
| Reads | `db.get(M, id)`, `db.query(M).filter(...).first()`, `db.execute(select(M).where(...))` |
| Writes | `obj.attr = v` (update), `db.delete(obj)`, `M(...)` + `db.add(obj)` (create), `query(...).delete()` |
| Guards | `if obj is None or obj.owner_id != user.id: raise HTTPException(...)` |
| Helpers | committed summary in `.keyhole/summaries/`, else Opaque |

## Not yet implemented

- `keyhole init` policy inference and `keyhole summarize` (LLM drafting of policies and summaries); the MVP reads hand-written or previously generated files.
- Interprocedural summaries of helpers inside the repo.
- Membership joins in adapters (the policy language and Lean core already support `member`).
- `keyhole confirm` dynamic replay, `--diff` mode, more frameworks (Express, Django).
