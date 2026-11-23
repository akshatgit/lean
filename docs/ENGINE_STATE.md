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
- third-party adapters can register through the `keyhole.adapters` entry-point group;
- the effect-free oracle's curated `EXT_FREE_MODULES` surface now includes host/OS/network
  modules (`platform`, `socket`, `fcntl`, `select`, `resource`, `getpass`, `sysconfig`,
  `psutil`); a module-level call into them holds no database handle and so cannot reach a
  modeled table (trust assumption A3). Only `module.attr(...)` calls match; methods on a
  returned instance stay opaque unless their receiver type is known. This is a generic
  stdlib/system completion, not a Langflow-specific rule.

The statements of Lean theorems `check_sound` and `check_witness` were not changed.

## Update 2026-11-23: LLM-Drafted Assumptions and the Iteration Loop

The dominant barrier to decisiveness is coverage, not proving: on the native Langflow scan
(396 endpoints, Claude policy + repository assumptions) 362 endpoints contain at least one
effect-capable operation the extractor cannot resolve, and the median blocked endpoint is
gated by roughly 38 distinct unresolved targets. An endpoint becomes decidable only when
*all* of its blockers clear, so per-target engine work alone cannot flip verdicts in bulk —
the greedy set-cover of shared blockers frees only ~56 of 362 endpoints across its top 25.

The designed home for the residue is the fingerprinted, review-gated assumptions file. It
keeps application-specific facts (what a given service locator returns, whether a specific
helper touches a table) out of the generic engine — the same anti-overfitting boundary this
document already states. An LLM/subagent is a sound fit as the *drafter*, never the verifier:

1. The worklist (`keyhole worklist --include-possible`) ranks unresolved targets by the
   endpoints each would free.
2. An LLM reads each top target's real body and drafts an assumption — `effects: [...]`,
   `effects: []`, or `returns_type: ...` — with a file/line/quote evidence block. It must
   withhold any target whose behavior depends on dynamic dispatch or a plugin hook rather
   than assert `effects: []` on it.
3. Entries are UNREVIEWED, so every verdict that uses one is amber until a human runs
   `keyhole review`, which digests the claim against the exact source it was written for.
4. Re-scan; resolved blockers drop out and the next, deeper layer surfaces in the worklist.
   The loop converges and, as it stalls, it *measures* the true ceiling — the targets that
   are genuinely undecidable statically.

Measured one iteration (8 LLM-drafted Category-1 assumptions from the worklist head; 7
Category-2 targets correctly withheld): UNKNOWN 131 -> 108, SAFE(assumed) 6 -> 9,
NO EFFECTS(assumed) 2 -> 4, POSSIBLE VIOLATION 236 -> 254 (the newly exposed accesses are
visible candidate findings, not hidden). Modeled accesses rose 2,302 -> 3,842 and blocker
records fell ~42%, with no soundness compromise (no `effects: []` asserted on a dynamic
dispatcher). These assumption entries are a prototype and are not committed.

For contrast, the generic engine fix above (host/OS/network modules) removed 169 blocker
records on the same scan but flipped zero endpoints — exactly because each affected endpoint
retains effect-capable blockers in its stack. The lesson for the next maintainer: general
sound rules reduce reviewer noise and help every app, but per-endpoint decisiveness on a
dynamic application is driven by the assumption loop. The remaining generic headroom is
stronger receiver type inference (sound, but hard), not blanket method-name purity, which the
oracle refuses by design because `x.get(...)` may be `session.get(Model, id)`.

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
3. Reduce the UNKNOWN endpoints. Drive this with the LLM-assumption iteration loop in the
   2026-11-23 update above, not with more Langflow-tuned engine rules; the largest residual
   causes are authorization-audit recursion/depth limits, dynamic `select` helpers,
   unavailable `session.exec`/`session.add` sources, and unresolved container/configuration
   calls. A repeatable `scan -> worklist -> LLM draft -> human review -> re-scan` harness and a
   human review pass over the drafted assumptions are the next concrete deliverables.
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
