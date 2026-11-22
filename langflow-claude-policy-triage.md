# Langflow example: Claude-authored policy report

Generated 2026-11-22 from the local `../langflow` clone. Claude Code 2.1.330 reviewed the
Langflow source read-only and emitted `langflow-keyhole.claude.policy.yaml`. Keyhole validated the
policy, scanned 380 non-test endpoints, and generated the report both natively and from the
`keyhole:local` Docker image. The native and Docker statistics are identical.

The policy is machine-generated and explicitly `status: unconfirmed`. It is evidence for evaluating
Keyhole, not an authoritative statement of Langflow's intended authorization model. No one at
Langflow was contacted and no vulnerability report was filed.

## Result

| Verdict | Endpoints |
|---|---:|
| SAFE | 45 |
| SAFE (assumed) | 6 |
| POSSIBLE_VIOLATION | 157 |
| VIOLATION (modeled) | 10 |
| UNKNOWN | 162 |
| **Total** | **380** |

The HTML coverage panel provides the important qualification: there are **0 proof-complete
endpoints**, 162 endpoints have no modeled effects, and 324 contain partial models. The 45 raw SAFE
results are therefore mostly “no modeled effects,” not authorization proofs. The six SAFE (assumed)
results prove their extracted effects only if Claude's unconfirmed policy/helper assumptions are
correct.

Verdicts are proven for the extracted model; extraction and policy are trusted inputs.

## Top remaining UNKNOWN causes

One endpoint can contribute multiple blockers.

| # | Reason | Call | Count |
|---:|---|---|---:|
| 1 | recursion/depth limit | `langflow.services.authorization.guards._audit_guard_decision` | 74 |
| 2 | dynamic query helper | `select` | 39 |
| 3 | source unavailable | `<unknown>` | 38 |
| 4 | recursion/depth limit | `langflow.services.authorization.guards.ensure_permission` | 37 |
| 5 | source unavailable | `session.exec` | 35 |
| 6 | unresolved result in control flow | `record['steps'].get` | 32 |
| 7 | source unavailable | `session.add` | 26 |
| 8 | recursion/depth limit | `langflow.services.authorization.audit._flush_audit_batch` | 17 |
| 9 | unresolved result in control flow | `settings.storage_type.lower` | 17 |
| 10 | unresolved result in returned response | `<unknown>` | 17 |

## Manual triage of every modeled VIOLATION

These are source-review leads, not confirmed vulnerabilities. All ten are false positives against
the generated policy or current AIR for the reasons below.

| Endpoint | Triage | Source-level reason |
|---|---|---|
| `GET /a2a/{flow_id}/.well-known/agent-card.json` | False positive | Public A2A discovery is intentional. The route requires an agent flow with A2A enabled and applies public-flow authorization when folder authentication is disabled. |
| `GET /authz/roles/{role_id}` | False positive / policy error | The route explicitly permits any authenticated user to read role metadata. Claude assigned `AuthzRole.read: false`, so the generated policy contradicts the documented route contract. |
| `GET /authz/shares/{share_id}` | False positive | The route resolves the resource owner, calls `ensure_share_permission(READ)`, and then applies `_user_can_see_share`; those dynamic helper semantics are not represented in AIR. |
| `PATCH /authz/shares/{share_id}` | False positive | `_ensure_can_administer_share` and `ensure_share_permission(UPDATE)` run before mutation. The generated `owner(created_by)` rule also does not express resource-owner/plugin administration. |
| `DELETE /authz/shares/{share_id}` | False positive | The same administration and share-permission checks run before deletion; helper/dynamic-resource semantics were not transferred. |
| `PATCH /deployments/snapshots/{provider_snapshot_id}` | False positive | The route groups all affected attachments and requires WRITE permission for every deployment before mutation. Loop/path-sensitive authorization is outside current AIR. |
| `GET /flows/public_flow/{flow_id}` | False positive | This route is intentionally public, calls `authorize_public_flow_access`, computes capabilities, and strips stored secret fields before returning the flow. |
| `PUT /monitor/messages/shared/{message_id}` | False positive | The row is resolved in a virtual flow namespace deterministically derived from the current user's ID; AIR cannot yet express that functional ownership relation. |
| `GET /projects/{project_id}/replacement-operations/{operation_id}` | False positive | The receipt is authorized against its stored project identity by `_authorize_replacement_result` or `_authorize_replacement_receipt_project_only` before return. |
| `PUT /projects/{project_id}` | False positive | Existing projects are owner-checked when cross-user fetch is disabled and always pass `ensure_project_permission(WRITE)` before update. Conditional and helper guards are not fully represented. |

## Reproduction

Native:

```bash
keyhole validate-policy langflow-keyhole.claude.policy.yaml
keyhole scan ../langflow \
  --policy langflow-keyhole.claude.policy.yaml \
  --format html \
  --out langflow-claude-policy-report.html \
  --stats langflow-claude-policy-stats.json
```

Docker:

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
