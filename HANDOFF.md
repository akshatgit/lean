# Keyhole: handoff notes

**Current handoff for the Langflow work on `review-fixes`, November 22, 2026:** [Verified results, reproduction commands, and open decisions](docs/langflow-handoff.md). The notes below are historical. The current scanner implements seven verdicts.

Context for continuing this project in a new Claude session. Read this first, then the README and the design doc.

- Repo: https://github.com/akshatgit/lean (package `keyhole`; final name undecided, "Warrant" was the front-runner)
- Design doc: https://claude.ai/artifact/CaGa9scNQ1VS79GQ4hGtrp
- Local work in progress: branch `review-fixes` (changes made by another AI after the MVP)

## What it is

A static analyzer for IDOR / object-level authorization bugs in web APIs (FastAPI + SQLAlchemy first). Positioning: **"mypy for authorization"**. A short policy file declares who may access what, and every commit is checked against it like a type check, with proofs.

Pipeline:
1. Source repo
2. Extraction by adapter plugins: 2a parse code (deterministic, `ast`); 2b fill gaps with committed helper summaries (LLM-drafted once, cached per version, marked "assumed")
3. AIR (Authorization Intermediate Representation), JSON: principal, params, effects (read/update/delete/create) with selector + guards
4. Policy inference (LLM + heuristics; not built yet)
5. Policy file `keyhole.policy.yaml`, confirmed by a developer
6. Lean 4 checker (`core/`), proven sound: `check_sound` (SAFE => Safe) and `check_witness` (every violation witness is real), proof by reflection, no `sorry`
7. Report: text / JSON / SARIF / HTML

## The one invariant

The adapter's AIR must OVER-APPROXIMATE what code can touch. Allowed: drop a guard, drop a filter conjunct, mark opaque. Forbidden: add a condition the code doesn't definitely enforce. A false SAFE is the worst bug; a false alarm is acceptable. The Lean proof is only as good as the extracted model.

## Verdicts (decided)

Three states, strictly defined:
- **SAFE**: proven, with a complete model and a confirmed policy, no caveats.
- **VIOLATION**: Lean counterexample, with a complete model (no dropped filters or checks, no unmodeled call before the row is *used*) and a confirmed policy.
- **UNKNOWN**: everything else, with reason tags sorted by usefulness: "counterexample found, blocked only by X" (former POSSIBLE_VIOLATION) > "policy not confirmed" > "code not modeled".
- Lint behavior: fail CI on VIOLATION; `--strict` also fails on UNKNOWN; report coverage as "% of endpoints proven".

## Review findings to implement (soundness spec)

Root cause of issues 1-4: the adapter read functions as straight lines. Replace with path-aware abstract interpretation:
- if/else: analyze each branch on a copy of the state; at merges, guards = intersection of the fall-through branches, effects = union.
- A path that definitely ends in an uncaught raise is excluded from the merge. That is how `if cond: raise` becomes a guard. Denial guards come from control flow, not syntax; analyze branch bodies, including DB effects.
- try/except/else/finally: the handler's entry state = merge of the states at every possibly-throwing point in the try. If matching is uncertain, assume it is caught. Keep effects from all parts.
- return: helper guards = intersection over all return paths (an early return of the row before a check removes that check).
- Loops: body guards don't hold after the loop.
- An unsupported condition contributes no guard. A violation after an unmodelled check is UNKNOWN (counterexample found), not VIOLATION.
- Allowlisting (`.get`/`.add`/`.update`) only when the receiver is proven non-DB by assignment, type, or config. Never by method name. Helpers that open their own session (e.g. Open WebUI `Chats.get_chat_by_id`) must not vanish.
- Invariant: if an unresolved call's result influences a returned response, a row selector, a DB mutation, or whether an authorization check is skipped, the endpoint is opaque and can't be SAFE. A call that only feeds a denial condition contributes no guard and does not make the endpoint opaque.
- Auth: `Security(...)` = `Depends(...)`; router/app-level `dependencies=[...]` count as authentication only if they resolve to a recognized principal dependency (not `Depends(get_db)`), and never create guards on principal attributes without an argument binding.
- Row-only helpers (`ensure_owner(doc, user)`) must return guards about their parameters, mapped back at the call site.
- `--stats PATH` writes stats to its own file; wording "VIOLATION (modeled)" plus the line "Verdicts are proven for the extracted model; extraction and policy are trusted inputs."
- Tests: every review snippet is a regression fixture; mutation tests: wrap the owner check in `if flag:`, in `try/except Exception`, or add an early `return document` before it; none may be SAFE.

## Langflow results so far

| | First run | Latest |
| --- | --- | --- |
| Endpoints | 411 (incl. tests) | 380 |
| UNKNOWN | 323 | 188 |
| POSSIBLE VIOLATION | n/a | 129 |
| VIOLATION | 9 (all likely false) | 6 (all "needs review") |
| SAFE / SAFE (assumed) | 76 / 3 | 0 / 10 |
| No modeled effects | counted as SAFE | 47 |

All 6 latest VIOLATIONs are probably false positives:
- `/a2a/.../agent-card.json`, `/flows/public_flow/{flow_id}`: protected by `authorize_public_flow_access`, which runs after load but before return.
- `/projects/{project_id}/replacement-operations/...`, `PUT /projects/{project_id}`: the owner check `not can_widen and project_user_id != current_user.id` was dropped.
- `PUT /monitor/messages/shared/{message_id}`: the dropped filter `flow_id == virtual_flow_id` is the authorization.
- `PATCH /deployments/snapshots/...`: the whole filter was dropped (selector `true`).

Do not report anything to Langflow until findings are triaged manually and confirmed.

## Next steps, in order

1. Implement the three-state verdicts and the VIOLATION rule above (completeness checked at the row's use point, not its load).
2. Path-aware analysis + review amendments (section above), with mutation tests.
3. Declare Langflow's central authz helpers in the policy (`authorize_public_flow_access`, `ensure_flow_permission`, `ensure_project_permission`, `filter_visible_resources`, `restrict_to_owned_or_visible_scope`, `authz.supports_cross_user_fetch` / `is_enabled`; that condition was dropped about 120 times). Treat audit/logging helpers as not data-relevant (378 depth-limit hits).
4. Model unknown booleans as symbolic flags instead of dropping the whole check: `not can_widen and owner != user` becomes the guard `can_widen or owner == user`.
5. Confirm the policy for the main models (Flow, Folder, MessageTable) so SAFE (assumed) becomes SAFE.
6. Run on Open WebUI (FastAPI + SQLAlchemy; data access via model helper classes; `get_verified_user` / `get_admin_user`; `has_access` helper) after helper analysis works.
7. Lint DX: `keyhole init`, inline ignores, baseline file, diff mode, pre-commit hook.

## Paper plan

- Claims: first soundly verified (Lean) checker for object-level authorization in web apps; plugin extraction pipeline that is honest about UNKNOWN; LLM assistance that cannot cause false SAFE (asymmetric trust, cached summaries, evaluation-confirmed witnesses).
- RQs: RQ1 rediscover known IDOR advisories and prove the fixes; RQ2 new bugs (responsible disclosure); RQ3 coverage (UNKNOWN rate and causes; Langflow baseline 21% modeled); RQ4 vs Semgrep/CodeQL; RQ5 LLM steps (policy inference accuracy, summaries ablation).
- Venues: SAIS '27 (USENIX Secure Agentic-AI Systems), papers due Feb 4, 2027; USENIX Security '27 Cycle 2 due Jan 26, 2027 (tight); CCS 2027 (~late April, unconfirmed); USENIX Security '28 Cycle 1 (~Aug 2027, likely target). Related work to verify: RoleCast (NDSS 2011), FixMeUp (2013), MACE (CCS 2014), AWS Cedar (OOPSLA 2024).
- Practical: find an academic co-author; get Rubrik's outside-work/IP policy in writing before publishing; prepare an artifact; arXiv preprint (also NIW/EB-1A evidence).

## Personal context (for career questions)

Senior SRE at Rubrik (~6 yrs experience; CVEs in Langflow, Flowise, vm2, Argo CD; USENIX Security '22). Green card: employer PERM at PWD stage (filed ~Oct 2026); EB-2 NIW self-petition recommended to decouple from employer, with this project as the proposed endeavor ("securing AI agent infrastructure").
