# Keyhole Engine Handoff

Keyhole is now an adapter-based IDOR analysis engine with a deterministic AIR-to-Lean checking
pipeline. FastAPI with SQLAlchemy is the built-in source adapter; application policy is external
input and may be written by a person or any policy generator. Langflow is the current evaluation
workload, not a source of application-specific engine rules.

The implementation and generated artifacts are present in the working tree but have not been
committed. The latest Python suite, Lean build, Docker build, and native-versus-Docker report check
all passed on 2026-11-22.

## Start Here

- Open [`langflow-claude-policy-docker-report.html`](langflow-claude-policy-docker-report.html) for
  the interactive Langflow report.
- Read [`langflow-claude-policy-triage.md`](langflow-claude-policy-triage.md) for interpretation,
  top UNKNOWN causes, and manual review of every modeled violation.
- Review [`langflow-keyhole.claude.policy.yaml`](langflow-keyhole.claude.policy.yaml) before trusting
  any policy-dependent result.
- Use [`langflow-claude-policy-docker-stats.json`](langflow-claude-policy-docker-stats.json) for
  machine-readable counts.

## Current Verification Status

| Check | Result |
|---|---|
| Python tests | 65 passed |
| Lean build | 10 jobs passed |
| Lean placeholders | No `sorry` or `admit` found |
| Policy validation | 63 resources and 252 rules accepted |
| Docker image | `keyhole:local` built successfully |
| Docker reproduction | Completed against the read-only Langflow mount |
| Native versus Docker stats | Identical |
| Langflow source changes | None |

The generated Langflow result contains 380 non-test endpoints:

| Verdict | Count |
|---|---:|
| SAFE | 45 |
| SAFE assumed | 6 |
| POSSIBLE VIOLATION | 157 |
| VIOLATION modeled | 10 |
| UNKNOWN | 162 |

The coverage panel is the correct way to interpret these counts. It reports zero proof-complete
endpoints, 162 endpoints with no modeled effects, and 324 partial models. Raw SAFE therefore does
not mean 45 endpoints received complete authorization proofs. All ten modeled violations were
manually reviewed against source and classified as false positives or generated-policy mismatches;
the other 370 endpoints were not manually security-reviewed.

## Trust Boundary

Lean proves verdicts for the AIR and policy it receives. It does not prove that Python extraction
captured every behavior or that the supplied policy matches the application's intended access
control. The adapter must always over-approximate reachable effects:

- never add a guard unless it holds on every represented path;
- never discard a database effect;
- use UNKNOWN or POSSIBLE VIOLATION when unresolved behavior may affect authorization;
- prefer a false alarm to a false SAFE.

The Claude policy is marked `status: unconfirmed`, and all its resources are `confirmed: false`.
Claude Code 2.1.330 produced it through a read-only source review. Keyhole does not call Claude or
another model during a scan. Policy generation is a separate replaceable step documented in
[`docs/POLICY_GENERATION.md`](docs/POLICY_GENERATION.md).

## Implemented Engine Behavior

The main implementation is in [`keyhole/adapters/fastapi_sqla.py`](keyhole/adapters/fastapi_sqla.py),
with the framework-neutral AIR, checker bridge, policy parser, CLI, and reports under `keyhole/`.
The notable behavior is:

- test files are excluded by default, with `--include-tests` available;
- `Depends`, `Security`, cross-module annotation aliases, and recognized app/router dependencies
  can identify authentication;
- path-aware analysis merges `if`, loop, return, raise, and conservative exception paths;
- incremental SQLAlchemy statements, supported selectors, and execution sites produce effects;
- repository helpers are analyzed to depth three, including returned rows and row-parameter guards;
- allowlisting is receiver/type aware, and unresolved result flow becomes opaque when it affects a
  response, selector, mutation, or authorization control flow;
- violations preceded by relevant opaque behavior or unmodeled checks become POSSIBLE VIOLATION;
- reports include filters, coverage warnings, assumptions, blockers, policy provenance, and stats;
- `keyhole validate-policy` validates externally generated policy files;
- third-party adapters can register through the `keyhole.adapters` entry-point group.

The statements of Lean theorems `check_sound` and `check_witness` were not changed.

## Reproduction

Build and test locally:

```bash
cd core
lake build
cd ..
pip install -e '.[dev]'
pytest -q
```

Validate and scan with the Claude-generated policy:

```bash
keyhole validate-policy langflow-keyhole.claude.policy.yaml
keyhole scan ../langflow \
  --policy langflow-keyhole.claude.policy.yaml \
  --format html \
  --out langflow-report.html \
  --stats langflow-stats.json
```

Reproduce in Docker:

```bash
docker build -t keyhole:local .
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$(realpath ../langflow):/target:ro" \
  -v "$(pwd):/workspace" \
  keyhole:local scan /target \
  --policy /workspace/langflow-keyhole.claude.policy.yaml \
  --format html \
  --out /workspace/langflow-claude-policy-docker-report.html \
  --stats /workspace/langflow-claude-policy-docker-stats.json
```

The scanner exits with status 1 for modeled violations by default. Add `--fail-on possible` to also
fail on POSSIBLE VIOLATION.

## Remaining Work

The next maintainer should prioritize correctness and generic coverage rather than tuning Keyhole to
Langflow-specific names.

1. Have an application owner review and correct the Claude-generated policy. One known mismatch is
   `AuthzRole.read: false`, while Langflow documents role metadata as readable by authenticated
   users.
2. Review the 157 POSSIBLE VIOLATION endpoints, starting with blockers shared by many routes.
3. Reduce the 162 UNKNOWN endpoints through generic modeling. The largest current causes are
   authorization-audit recursion/depth limits, dynamic `select` helpers, unavailable `session.exec`
   or `session.add` sources, and unresolved container/configuration calls.
4. Add another independent application fixture or adapter before making broad claims about
   framework-agnostic coverage. The engine boundary is generic, but the only built-in source adapter
   remains FastAPI with SQLAlchemy.
5. Review the complete working-tree diff and commit the engine, tests, documentation, Dockerfile,
   citation metadata, Claude policy, and canonical report artifacts together or in deliberate
   separate commits.

## Repository State

The working tree contains substantial uncommitted changes. Canonical Langflow artifacts were kept;
older Codex-policy, pre-fix, and duplicate native reports were removed. Deleted reports were
generated files and can be recreated, but they were never committed and therefore cannot be
restored through Git.

No Langflow issue, disclosure, or external security report has been created.
