# Keyhole Langflow handoff

Work stopped at the user's request on November 22, 2026. The implementation checkpoint is `1177c76` on `review-fixes`. Keyhole completes the Langflow scan, but 367 of 396 endpoint verdicts still require investigation. A usable, decisive verifier for every endpoint remains an open goal.

## Verified checkpoint

The full suite passed **278 tests**. The scan used the local Langflow checkout at `21381e5b2964fb4c714dc91fcd5187d4cfc2a67f`, Python 3.11.4, the repository's Langflow policy and assumptions, and the Lean checker. The supplied policy is unconfirmed.

| Endpoint verdict | Count |
| --- | ---: |
| SAFE | 0 |
| SAFE (assumed) | 6 |
| VIOLATION | 0 |
| POSSIBLE VIOLATION | 236 |
| UNKNOWN | 131 |
| NO EFFECTS | 21 |
| NO EFFECTS (assumed) | 2 |

Lean proved **478 of 2,302 modeled accesses** under the supplied policy. The remaining 1,824 produced possible violations. Of the 131 UNKNOWN endpoints, 46 have every modeled access proved and an unresolved operation that could touch more data. The other 85 have zero modeled accesses. In all, 362 endpoints contain an effect-capable unmodeled operation.

The final change modeled a session query used as the first iterable of a comprehension. In the full scan this exposed ten more accesses. `GET /policy-bundle/history` moved from UNKNOWN to SAFE (assumed) when the read of `PolicyBundleRevision` became visible. The adapter still checks calls inside the comprehension separately.

## Reproduce the report

Run from the Keyhole repository root with the sibling Langflow checkout present. The filenames below refer to existing inputs. The scan runs locally and requires no LLM.

```sh
(cd core && lake build)
.venv/bin/python -m pytest -q
.venv/bin/python -m keyhole scan ../langflow \
  --policy langflow-keyhole.claude.policy.yaml \
  --assumptions langflow.assumptions.yaml \
  --format html --out langflow-claude-policy-docker-report.html \
  --stats /tmp/keyhole-langflow-stats.json
```

Open `langflow-claude-policy-docker-report.html` in the repository root. Git ignores the generated HTML. The tracked file `langflow-claude-policy-docker-stats.json` had pre-existing local modifications and was left alone. The command above writes fresh stats separately.

## Where to resume

1. **Trace one real blocker.** For `POST /agentic/execute/{flow_name}`, the report shows five direct helper call sites and one modeled Flow read. `execute_flow_file` contributes 773 effect-capable records across 371 distinct source lines. `_resolve_assistant_context` contributes 283 across 147 lines. Repeated paths account for part of the volume. The endpoint verdict is POSSIBLE VIOLATION. Use the report's helper trace to inspect a call site before proposing a general rule.
2. **Distinguish missing code from unsupported semantics.** Four UNKNOWN routes share the `CatalogPolicyService()` constructor blocker. Its registration decorator passes the class to a service manager. The decorator returns the class, but that alone does not establish what registration or construction can do. Inspect the decorator and manager together before changing the purity oracle. Run `keyhole worklist` with the same repo, policy and assumptions and `--include-possible` to include all inconclusive endpoints with effect-capable blockers.
3. **Measure generalization before adding more rules.** On the independent FastAPI full-stack template at `77e550a73bb49dd2967622c5ed11bf7a49603c93`, the five item CRUD routes reached SAFE (assumed) under a trial owner-or-superuser policy on Python 3.14. That was a five-route spot check. A frozen multi-app benchmark with independently labeled outcomes, including missed accesses and false SAFE results, is still outstanding.
4. **Obtain a policy decision from the application owner.** The scanner cannot establish the intended authorization policy from application behavior. Confirmation requires review. It can change how counterexamples are reported, but it cannot recover a missing row access or resolve dynamic dispatch.

For implementation context, the main extraction logic is in [the FastAPI adapter](../keyhole/adapters/fastapi_sqla.py), effect-free call classification is in [the purity oracle](../keyhole/adapters/purity.py), and endpoint verdict gating is in [the checker](../keyhole/checker.py). The latest correctness regressions cover owner-field overwrite order (`acf016d`), SQL filter conversions (`df89f0c`), and caller-variable reassignment (`e8670b0`).
