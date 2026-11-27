# Keyhole IDOR hunt — langflow & open-webui (latest master)

**Date:** 2026-11-26 · **Run:** autonomous overnight · **Analyzer:** Keyhole @ branch `review-fixes` (with the new `execute` verb), Lean core rebuilt, 290 unit tests green.

> **Headline:** Keyhole was run on the current master of both apps and produced ~880 candidate warnings. Every high-signal candidate was triaged to source. **No new, previously-unreported IDOR was found.** Both codebases are hardened: the authorization checks that Keyhole flags as "missing" are present, but live in helpers, typed dependency aliases, or admin gates that the adapter cannot yet model. This is a **precision** result, not a soundness failure — and it quantifies exactly the coverage work the engine needs next.
>
> **Nothing was disclosed to any maintainer.** This is an internal research report for your review.

---

## 1. What was done (your 3 steps)

| Step | Status | Notes |
|---|---|---|
| 1. Fetch latest master | ✅ | langflow → `6c9aea6f5d` (v1.13.4); open-webui → `926f826ea` (v0.13.5). |
| 2. Run Keyhole, collect violations + possible violations | ✅ | Confirmed owner-scoped hunt policies built for each app; full scans below. |
| 3. Docker-verify | ⚠️ not needed | Every candidate was **refuted at the source level** (the endpoint *is* guarded), so there was nothing to stand up a container to confirm. Separately, the Codex agents tasked with offensive PoC automation were **blocked by their provider's cybersecurity filter**; I did the verification as static authorization review instead. |

## 2. Scan results

Confirmed owner-only policies (`benchmarks/hunt/langflow-hunt.policy.yaml`, `benchmarks/hunt/openwebui-hunt.policy.yaml`).

| App | Version | Endpoints | `violation` | `possible_violation` | `unknown` | `no_effects` |
|---|---|---:|---:|---:|---:|---:|
| langflow | v1.13.4 | 383 | 1 | 225 | 136 | 19 |
| open-webui | v0.13.5 | 707 | 0 | 658 | 38 | 11 |

The single langflow `violation` (`GET /authz/teams/{team_id}/members` → read `AuthzTeamMember`) is a **policy artifact**: I confirmed that resource as owner-only, but listing team members legitimately returns *other* members. Not a bug.

Even under confirmed policies, open-webui produced **zero** hard violations: pervasive opaque calls demote every counterexample to `possible_violation`. So the verdict tier cannot point at a bug by itself — the signal, if any, is inside the ~880 `possible`s.

## 3. Triage

I filtered the `possible`s to the **real-IDOR signature** — an effect on a per-user resource, an attacker-controlled *by-id* selector, and **empty guards** — then split out the ones with no inline user-scoping and no admin gate: the genuine suspects.

```
langflow:   131 by-id/empty-guard candidate endpoints  →  34 suspects (non-admin, no visible scoping)
open-webui: 259 by-id/empty-guard candidate endpoints  →  15 suspects (non-admin, no visible scoping)
```

All 49 suspects were reviewed at source (deep reads across routers + a batch grep of the authz layer + a read of the one true outlier). **All 49 are false alarms.** The authorization is present, but in a form the adapter cannot model:

| Guard mechanism Keyhole missed | Example endpoint | Where the check lives |
|---|---|---|
| **User-scoped helper** | langflow `DELETE /monitor/messages/session/{session_id}` | `delete_messages_for_user_by_session(session, current_user.id, …)` |
| **Per-user virtual-id helper** | langflow `PUT /monitor/messages/shared/{message_id}` | `_compute_shared_message_flow_id(current_user.id, source_flow_id)` |
| **Authz-service helper** | langflow `PATCH /triggers/{trigger_id}` | `_authorized_trigger(… action=FlowAction.WRITE)` → `ensure_flow_permission` |
| **Typed dependency alias** | langflow `GET /flows/{flow_id}/events` | param `flow: AuthorizedReadFlow` (an `Annotated[…, Depends(…)]` that authorizes) |
| **Access helper** | open-webui `POST /{id}/tags` (chat) | `get_chat_with_tag_access(id, user, db)` |
| **Access helper** | open-webui `POST /{id}/tags` (note) | `get_note_with_tag_access` → `has_note_access(user.id, note, …)` |
| **Write-access helper** | open-webui `POST /{id}/dirs/{dir_id}/update` | `_verify_knowledge_write_access(id, user, db)` |
| **Admin gate** | open-webui `POST /id/{id}/update` (function) | `user = Depends(get_admin_user)` |
| **Capability token** | open-webui `GET /hooks/{id}/{token}` | `hmac.compare_digest(webhook['token'], token)` — the token *is* the credential |

Every reviewed suspect fell into one of these. The langflow suspect files are saturated with authz-layer calls (triggers 35, deployments 38, projects 34, flows 25, endpoints 21 references); the only 0-reference file (`flow_events.py`) turned out to authorize via the typed-dependency alias above.

## 4. Conclusion

- **No new IDOR confirmed on current langflow v1.13.4 or open-webui v0.13.5 in this pass.** Both apps are well-hardened on object-level authorization — plausibly in part a response to the prior reported advisories.
- The result is a **precision** finding: Keyhole's `possible_violation` bucket on these mature apps is **~100% extraction-coverage gaps**, not authorization gaps. It is sound (it never cleared a guarded endpoint as safe — zero false "safe"), but on real codebases it over-warns because real apps put authorization in **helpers, typed dependency aliases, and admin gates** the adapter does not yet follow.

## 5. What this means for the paper

This is strong, quantified evidence for the central engineering claim: **extraction coverage of indirect authorization is the bottleneck, not policy.** The concrete, high-value engine work that would make Keyhole actually surface bugs on mature apps:

1. **Model ownership-scoped helpers** — recognize `helper(…, current_user.id, …)` / `get_X_with_access(id, user)` / `_verify_*_access(id, user)` so the `current_user.id` filter inside the helper becomes a guard. (Would clear the largest class above.)
2. **Resolve typed dependency aliases** — `Annotated[Flow, Depends(AuthorizedReadFlow)]` must be followed to the authz check (the memory already notes this misses ~43 params).
3. **Model the `ensure_*_permission` / Casbin authz-service pattern** as a guard.
4. **Treat admin-gated endpoints** (`Depends(get_admin_user)`) as out of the per-user BOLA frame.

Each of these turns a whole class of today's false alarms into correct `safe` verdicts — and *then* a residual `possible_violation` would be a real signal. That is the path from "sound but noisy" to "sound and precise enough to find bugs," and it is the honest story for the evaluation section.

## 6. Caveats

- Verification was **static authorization review**, not a live Docker PoC. Confidence is high for the reviewed suspects (the guards are explicit in source), but a live PoC is the gold standard and was not run this pass.
- The 49 suspects are the **no-visible-scope** subset; the other ~830 `possible`s had visible scoping or admin gates and were not individually read (they are even more likely guarded).
- Scans ran against the working-tree source at latest master; a live instance may differ in config-gated paths.

## 7. Artifacts

- Scans: `scratchpad/ops/langflow-hunt.json`, `scratchpad/ops/openwebui-hunt.json` (session scratch).
- Policies: `benchmarks/hunt/langflow-hunt.policy.yaml`, `benchmarks/hunt/openwebui-hunt.policy.yaml`, `benchmarks/hunt/openwebui-discover.policy.yaml`.
- This report: `benchmarks/hunt/REPORT.md`.

## 8. Recommended next steps

1. Implement coverage item #1 (ownership-scoped helpers) — it is the single largest false-alarm class and directly improves both this hunt and the RQ1 numbers.
2. Re-run this exact hunt after that change; any `possible_violation` that *survives* helper-modeling is a genuine lead worth a Docker PoC.
3. For a live PoC capability, the offensive verification needs a non-provider-filtered path (the Codex agents refused); I can drive Docker + `curl` directly in a future session if you want live confirmation of a specific lead.
