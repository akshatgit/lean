"""Change #2: policy declarations are bound by identity and screened before they apply.

A declaration (adapter.ignore_calls) is a human/LLM claim, not a proof.  It may only
suppress a call the adapter cannot otherwise see, and only when the call cannot reach
the database through what it is handed.  Every refused declaration must leave the call
classified exactly as if undeclared -- never silently green."""
from pathlib import Path

import pytest

from keyhole.adapters import FastAPISQLAlchemyAdapter
from keyhole.checker import check_endpoints
from keyhole.policy import load_policy
from keyhole.summaries import load_summaries

FIXTURE = Path(__file__).parent / "fixtures" / "declaration_binding"
GREEN = {"safe", "safe_assumed", "no_effects", "no_effects_assumed"}


@pytest.fixture(scope="module")
def results():
    policy = load_policy(FIXTURE / "keyhole.policy.yaml")
    endpoints = FastAPISQLAlchemyAdapter().extract(FIXTURE, load_summaries(FIXTURE), policy=policy)
    return {r.endpoint.key: r for r in check_endpoints(endpoints, policy)}


def ids(res):
    return set(res.endpoint.assumptions)


def effect_capable_opaque(res):
    return [o for o in res.endpoint.opaque if o.may_have_effects]


# ---- 2a: refused when handed a way to reach the database --------------------------------

@pytest.mark.parametrize("key", [
    "GET /passed-session/{doc_id}",
    "GET /passed-row/{doc_id}",
    "GET /passed-callable/{doc_id}",
    "GET /session-receiver/{doc_id}",
])
def test_declared_call_handed_db_access_is_not_suppressed(results, key):
    res = results[key]
    assert res.verdict not in GREEN, (key, res.verdict)
    assert res.verdict == "unknown"
    assert effect_capable_opaque(res), "the refused call must become an effect-capable opaque"
    assert not any(i.startswith("ignore:") or i.startswith("declared-free:") for i in ids(res))


def test_declared_call_handed_only_scalars_is_still_suppressed(results):
    res = results["GET /passed-scalars/{doc_id}"]
    assert res.verdict == "safe_assumed"
    assert "ignore:record" in ids(res)
    assert not effect_capable_opaque(res)


# ---- 2b: bound by identity, never by a bare last segment ----------------------------------

def test_bare_declaration_does_not_bind_unrelated_repo_function(results):
    res = results["GET /name-collision/{doc_id}"]
    assert res.verdict == "unknown"          # other.foo is analysed, and is not provably free
    assert "ignore:foo" not in ids(res) and "declared-free:foo" not in ids(res)
    # other.foo's BODY was analysed (not vouched for by the name): its unreadable inner
    # call is what keeps the endpoint from being green.
    assert any("vendor.transmit" in o.call for o in effect_capable_opaque(res))


def test_bare_declaration_still_binds_unreadable_callee(results):
    res = results["GET /leaf-unreadable/{doc_id}"]
    assert res.verdict == "safe_assumed"
    assert {"ignore:foo", "declared-free:foo"} & ids(res)


# ---- 2c: a declaration the adapter can refute is rejected --------------------------------

def test_refuted_declaration_is_rejected_and_read_is_modeled(results):
    res = results["GET /refuted/{doc_id}"]
    assert "ignore:peek" not in ids(res) and "declared-free:peek" not in ids(res)
    reads = [e for e in res.effects if e.effect.kind == "read" and e.effect.resource == "Doc"]
    assert reads, "peek's visible read of Doc must be modeled, not suppressed"
    assert res.verdict == "violation"        # read by id, no ownership check, confirmed policy


def test_declared_dependency_handed_session_is_analysed_not_trusted(results):
    res = results["GET /declared-dependency-with-session/{doc_id}"]
    assert "ignore:get_audit_ctx" not in ids(res)
    # Its body is visibly empty, so analysis PROVES it irrelevant: clean SAFE, no assumption.
    assert res.verdict == "safe"


def test_no_green_verdict_rests_on_a_refused_declaration(results):
    for key, res in results.items():
        if res.verdict in GREEN:
            assert not effect_capable_opaque(res), key
