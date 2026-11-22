"""Regression tests for the soundness/correctness fixes (S1, S2, S4, S6, S10, C5, C8)."""
import shutil
from pathlib import Path

from keyhole.adapters import FastAPISQLAlchemyAdapter
from keyhole.checker import check_endpoints
from keyhole.policy import load_policy
from keyhole.summaries import load_summaries

FIXTURES = Path(__file__).parent / "fixtures"


def scan(path: Path):
    policy = load_policy(path / "keyhole.policy.yaml")
    endpoints = FastAPISQLAlchemyAdapter().extract(path, load_summaries(path), policy=policy)
    return {r.endpoint.key: r for r in check_endpoints(endpoints, policy)}, policy


# ---- S3: dependency bodies are analyzed (the dominant FastAPI authz idiom) ----

def test_dependency_ownership_guard_is_modeled():
    results, _ = scan(FIXTURES / "dependency_authz")
    read = results["GET /api/documents/{doc_id}"]
    # The read + owner guard come from inside Depends(get_document).
    assert read.verdict == "safe"
    assert any(e.effect.resource == "Document" and e.effect.kind == "read" for e in read.effects)


def test_dependency_without_ownership_check_is_a_violation():
    results, _ = scan(FIXTURES / "dependency_authz")
    leaky = results["GET /api/leaky/{doc_id}"]
    assert leaky.verdict == "violation"


# ---- S1: no modeled effects is never SAFE ----

def test_no_effects_is_its_own_verdict_not_safe():
    results, _ = scan(FIXTURES / "no_effects")
    res = results["GET /ping"]
    assert res.verdict == "no_effects"
    assert res.verdict != "safe"


# ---- S2: a query wrapped in list(...) is still modeled ----

def test_container_wrapped_query_is_modeled():
    results, _ = scan(FIXTURES / "container_query")
    res = results["GET /docs"]
    assert res.verdict != "no_effects"
    assert any(e.effect.resource == "Document" and e.effect.kind == "read" for e in res.effects)


# ---- S6: setattr(row, ...) is an update ----

def test_setattr_is_modeled_as_update():
    results, _ = scan(FIXTURES / "setattr_update")
    res = results["PATCH /docs/{doc_id}"]
    assert any(e.effect.kind == "update" and e.effect.resource == "Document" for e in res.effects)
    assert res.verdict == "safe"  # owner-guarded


# ---- Bug 1: a dependency re-used as a plain helper must not transfer its guard ----

def test_dependency_called_as_helper_does_not_launder_guard():
    results, _ = scan(FIXTURES / "dependency_as_helper")
    res = results["GET /docs/{doc_id}"]
    # The endpoint loads the row with no ownership check; calling render(doc) (whose
    # parameter is Depends(get_document)) must NOT transfer get_document's guard.
    assert res.verdict == "violation"


# ---- Bug 2: an unguarded sibling read of the same model must survive ----

def test_dependency_sibling_read_is_not_overwritten():
    results, _ = scan(FIXTURES / "dependency_sibling")
    res = results["GET /docs/{doc_id}"]
    # get_document reads `other` (unguarded) and `doc` (guarded) of the same model;
    # the returned-row binding must not overwrite the sibling read -> still a violation.
    assert res.verdict == "violation"
    reads = [e for e in res.effects if e.effect.kind == "read" and e.effect.resource == "Document"]
    assert len(reads) >= 2


# ---- Bug 3: the user model having policy rules must not hide the real principal ----

def test_user_resource_does_not_hide_principal(tmp_path):
    fixture = tmp_path / "app"
    shutil.copytree(FIXTURES / "setattr_update", fixture)
    policy_path = fixture / "keyhole.policy.yaml"
    # Add a User resource (no principal.dependencies declared). `user: User = Depends(
    # get_current_user)` must still be recognised as the caller.
    policy_path.write_text(
        policy_path.read_text() + "  User:\n    confirmed: true\n    read: owner(id)\n"
    )
    results, _ = scan(fixture)
    res = results["PATCH /docs/{doc_id}"]
    assert res.endpoint.principal_binding == "user"
    assert res.verdict == "safe"


# ---- C8: a violation on an unconfirmed policy is only a lead, not a finding ----

def test_unconfirmed_policy_demotes_violation(tmp_path):
    fixture = tmp_path / "app"
    shutil.copytree(FIXTURES / "dependency_authz", fixture)
    policy_path = fixture / "keyhole.policy.yaml"
    policy_path.write_text(policy_path.read_text().replace("confirmed: true", "confirmed: false"))
    results, _ = scan(fixture)
    assert results["GET /api/leaky/{doc_id}"].verdict == "possible_violation"
