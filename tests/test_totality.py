"""Move 1: opacity is split into `may_have_effects` / `may_block`, and the call walker is total.

Soundness contract under test:
  * a call that is not positively modeled blocks SAFE unless the purity oracle PROVES it
    cannot touch the database (by import identity, receiver type, or transitive closure);
  * a provably effect-free call never blocks SAFE, even if its result is unknown.
"""
from pathlib import Path

import pytest

from keyhole import air
from keyhole.adapters import FastAPISQLAlchemyAdapter
from keyhole.checker import EndpointResult, _aggregate, check_endpoints
from keyhole.policy import load_policy
from keyhole.summaries import load_summaries

FIXTURES = Path(__file__).parent / "fixtures"
NOT_PROVEN = {"safe", "safe_assumed", "no_effects"}


def scan(name: str):
    path = FIXTURES / name
    policy = load_policy(path / "keyhole.policy.yaml")
    endpoints = FastAPISQLAlchemyAdapter().extract(path, load_summaries(path), policy=policy)
    return {r.endpoint.key: r for r in check_endpoints(endpoints, policy)}


@pytest.fixture(scope="module")
def skips():
    return scan("totality_skips")


@pytest.fixture(scope="module")
def traps():
    return scan("totality")


@pytest.fixture(scope="module")
def pure():
    return scan("totality_pure")


def effect_opaque(res):
    return [o for o in res.endpoint.opaque if o.may_have_effects]


# ---- the five known walker-skip endpoints (mirrored) -------------------------------------

LANGFLOW_SKIP_MIRRORS = [
    ("GET /files/download/{flow_id}/{file_name}", "_legacy_flow_storage_allowed"),  # BoolOp
    ("GET /files/list/{flow_id}", "_legacy_flow_storage_allowed"),                  # BoolOp in try
    ("PUT /migration/destinations/{record_id}", "_state"),                          # dict splat in return
    ("GET /agentic/check-config", "get_enabled_providers_for_user"),                # tuple unpack
    ("GET /catalog-policy/usage/flows", "_cached_flow_component_usage"),            # tuple unpack
]


@pytest.mark.parametrize("key,callee", LANGFLOW_SKIP_MIRRORS)
def test_langflow_skip_patterns_are_unknown_never_safe(skips, key, callee):
    res = skips[key]
    assert res.verdict not in NOT_PROVEN
    assert res.verdict == "unknown"
    assert any(callee in o.call for o in effect_opaque(res)), [o.call for o in res.endpoint.opaque]


def test_modeled_part_of_a_skip_endpoint_is_still_proven(skips):
    # The owner-checked dependency read is modeled and safe; only the skipped call
    # keeps the endpoint from SAFE.
    res = skips["GET /files/download/{flow_id}/{file_name}"]
    assert [e.verdict for e in res.effects] == ["safe"]


@pytest.mark.parametrize("key", [
    "GET /skip/if-test/{flow_id}", "GET /skip/ifexp/{flow_id}", "GET /skip/subscript/{flow_id}",
    "GET /skip/comprehension", "GET /skip/for-iter", "GET /skip/with-item",
    "DELETE /skip/closure/{flow_id}", "GET /skip/lambda/{flow_id}", "GET /skip/kwarg/{flow_id}",
    "GET /skip/fstring/{flow_id}", "GET /skip/raise/{flow_id}",
    "GET /skip/unresolved-dependency/{flow_id}",
])
def test_every_catalogued_skip_position_is_unknown(skips, key):
    res = skips[key]
    assert res.verdict == "unknown"
    assert effect_opaque(res)


def test_no_endpoint_in_the_skip_fixture_is_safe(skips):
    assert not [k for k, r in skips.items() if r.verdict in NOT_PROVEN]


# ---- purity must come from identity / receiver type / closure, never a method name -------

TRAPS = [
    "GET /trap/untyped-receiver/{doc_id}",     # .get() on a value of unknown type
    "GET /trap/rebound-name/{doc_id}",         # name was a dict, then rebound
    "GET /trap/dict-subclass/{doc_id}",        # dict subclass overriding .get()
    "GET /trap/annotated-dict/{doc_id}",       # `dict` annotation may hold that subclass
    "GET /trap/override/{doc_id}",             # base method pure, override reads
    "GET /trap/property/{doc_id}",             # calling a property's value
    "GET /trap/closure-unknown/{doc_id}",      # helper with an unidentified callee
    "GET /trap/hidden-session/{doc_id}",       # helper with no db parameter at all
    "GET /trap/mutual-recursion/{doc_id}",     # recursion cycle containing a read
    "GET /trap/shadowed-builtin/{doc_id}",     # module-level `len` is not the builtin
    "GET /trap/callback-kw/{doc_id}",          # sorted(key=<reads>)
    "GET /trap/higher-order/{doc_id}",         # map(<reads>, ...)
    "GET /trap/constructor/{doc_id}",          # __init__ reads
    "GET /trap/decorated-closure/{doc_id}",    # decorated nested function
    "GET /trap/legacy-query-iter/{doc_id}",    # list(query) executes it
    "PATCH /trap/untracked-write/{doc_id}",    # attribute write on an untracked object
    "GET /trap/class-dependency/{doc_id}",     # bare Depends() injecting a class
    "GET /trap/endpoint-decorator/{doc_id}",   # unknown wrapper around the handler
]


@pytest.mark.parametrize("key", TRAPS)
def test_unproven_call_blocks_safe(traps, key):
    res = traps[key]
    # the owner-checked load on its own is safe, so only the trap keeps this from SAFE
    assert all(e.verdict == "safe" for e in res.effects)
    assert res.verdict == "unknown"
    assert effect_opaque(res)


def test_decorated_helper_is_not_modeled_as_its_body(traps):
    # load_checked() raises for foreign rows, but its decorator swallows that.  Inlining
    # the body would attach an ownership guard the call does not enforce.
    res = traps["GET /trap/decorated-helper/{doc_id}"]
    assert res.verdict == "unknown"
    assert not res.effects
    assert any(o.reason == "decorated_helper" for o in res.endpoint.opaque)


@pytest.mark.parametrize("key", [
    "DELETE /stale/tuple-rebind/{doc_id}/{other_id}",
    "DELETE /stale/unknown-rebind/{doc_id}/{other_id}",
    "DELETE /stale/loop-rebind/{doc_id}",
])
def test_rebound_row_variable_loses_its_guard(traps, key):
    # `doc` was owner-checked, then rebound to an unchecked object and deleted.  The
    # delete must not be reported as a guarded delete of the checked row.
    res = traps[key]
    assert res.verdict not in NOT_PROVEN
    assert not any(e.effect.kind == "delete" and e.verdict == "safe" for e in res.effects)
    assert any("session.delete" in o.call for o in effect_opaque(res))


def test_no_endpoint_in_the_trap_fixture_is_safe(traps):
    assert not [k for k, r in traps.items() if r.verdict in NOT_PROVEN]


# ---- provably effect-free calls do NOT block SAFE ----------------------------------------

def test_provably_pure_calls_do_not_block_safe(pure):
    res = pure["GET /pure/{doc_id}"]
    assert res.verdict == "safe"
    assert [e.verdict for e in res.effects] == ["safe"]
    assert not effect_opaque(res)


def test_value_only_opacity_is_recorded_but_does_not_block_safe(pure):
    res = pure["GET /pure/{doc_id}"]
    value_only = [o for o in res.endpoint.opaque if not o.may_have_effects]
    assert value_only, "the unknown-result calls should still be visible as may_block opacity"
    assert all(o.may_block for o in value_only)


def test_pure_endpoint_without_effects_is_no_effects_not_unknown(pure):
    assert pure["GET /pure-no-effects"].verdict == "no_effects"


# ---- checker: the two flags are independent ----------------------------------------------

def _endpoint(opaque):
    ep = air.Endpoint("GET", "/x", "f.py", 1)
    ep.opaque = opaque
    return ep


def test_opaque_json_carries_both_flags():
    data = air.Opaque("f(...)", "source_unavailable", 3, may_block=True, may_have_effects=False).to_json()
    assert data["may_block"] is True and data["may_have_effects"] is False
    assert air.Opaque("f(...)", "x").may_have_effects is True  # default stays conservative


def test_aggregate_zero_effects():
    block_only = _endpoint([air.Opaque("f(...)", "r", 1, may_block=True, may_have_effects=False)])
    effectful = _endpoint([air.Opaque("f(...)", "r", 1, may_block=False, may_have_effects=True)])
    assert _aggregate(EndpointResult(block_only), block_only) == "no_effects"
    assert _aggregate(EndpointResult(effectful), effectful) == "unknown"


def test_aggregate_safe_effect_is_blocked_only_by_effect_capable_opacity(pure, traps):
    safe = pure["GET /pure/{doc_id}"]
    assert safe.endpoint.opaque and safe.verdict == "safe"
    blocked = traps["GET /trap/untyped-receiver/{doc_id}"]
    assert all(e.verdict == "safe" for e in blocked.effects) and blocked.verdict == "unknown"


def test_may_block_opacity_still_demotes_a_violation():
    # value-only opacity before an effect keeps a counterexample a lead, not a finding
    path = FIXTURES / "totality"
    policy = load_policy(path / "keyhole.policy.yaml")
    ep = air.Endpoint("GET", "/d/{doc_id}", "f.py", 1)
    ep.params["doc_id"] = air.Param("doc_id", "path", "int")
    ep.effects = [air.Effect("read", "Doc", air.eq(air.fld("id"), air.param("doc_id")), [], 10)]
    ep.opaque = [air.Opaque("check(...)", "unresolved_result_in_control_flow", 5,
                            may_block=True, may_have_effects=False)]
    (res,) = check_endpoints([ep], policy)
    assert res.effects[0].verdict == "possible_violation"
    assert res.verdict == "possible_violation"
    ep.opaque = []
    (res,) = check_endpoints([ep], policy)
    assert res.verdict == "violation"
