# External policy generation

Keyhole does not ask an LLM to decide whether an endpoint is safe. The scanner is deterministic:
an adapter extracts AIR, then the Lean checker compares AIR with a policy. Policy authoring is a
separate, replaceable step and can be performed by a person, Claude Code, another model, or an
organization's existing authorization specification.

An external generator must emit YAML accepted by `keyhole validate-policy POLICY`. Generated
resources must remain `confirmed: false` until a human responsible for the application reviews
them. Consequently, a generated policy can produce `SAFE (assumed)`, never unconditional `SAFE`.

## Generator prompt contract

Give the generator read-only access to the target repository and require YAML with this shape:

```yaml
generated_by: "generator name and version"
status: unconfirmed
principal:
  id: current_user.id
  bypass: current_user.is_superuser
  dependencies: [get_current_user]
  types: [CurrentUser]
helpers:
  ensure_document_access: "owner(owner_id)"
adapter:
  ignore_calls: [known_non_database_call]
resources:
  Document:
    confirmed: false
    read: "owner(owner_id) or visibility == 'PUBLIC'"
    update: "owner(owner_id)"
    delete: "owner(owner_id)"
    create: "owner(owner_id)"
```

The only supported expressions are `true`, `false`, `owner(FIELD)`, `member(FIELD)`, equality
against a constant or principal attribute, and parenthesized `and`/`or`. A helper rule is a trusted
assumption and may be emitted only when the source establishes it on every normal return. Project
specific calls belong in `adapter.ignore_calls` only when their receiver or implementation proves
they cannot touch application data.

## Reproducible workflow

```bash
keyhole validate-policy generated.policy.yaml
keyhole scan TARGET_REPO \
  --policy generated.policy.yaml \
  --format html \
  --out keyhole-report.html \
  --stats keyhole-stats.json
```

The HTML report displays `generated_by` and `status`. Those fields are provenance, not proof. Lean
proves verdicts for AIR plus policy; source extraction and policy intent remain trusted inputs.
