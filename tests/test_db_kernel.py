"""Move 2: generic SQLAlchemy/SQLModel kernel idioms.

Each capability is tested twice: a positive route where the authorization really is in
the code (must be SAFE) and a negative twin where it is not (must be a violation or a
lead, never green).  A capability that only had the positive half could be producing
SAFE for the wrong reason.
"""
from pathlib import Path

import pytest

from keyhole.adapters import FastAPISQLAlchemyAdapter
from keyhole.checker import check_endpoints
from keyhole.policy import load_policy
from keyhole.summaries import load_summaries

FIXTURE = Path(__file__).parent / "fixtures" / "db_kernel"
GREEN = {"safe", "safe_assumed", "no_effects", "no_effects_assumed"}


@pytest.fixture(scope="module")
def kernel():
    policy = load_policy(FIXTURE / "keyhole.policy.yaml")
    endpoints = FastAPISQLAlchemyAdapter().extract(FIXTURE, load_summaries(FIXTURE), policy=policy)
    return {r.endpoint.key: r for r in check_endpoints(endpoints, policy)}


POSITIVE = [
    "GET /conditional/sql-and",
    "GET /generic/owned/{doc_id}",       # select(model) with model/columns bound at the call site
    "GET /builder/owned/{doc_id}",       # statement returned by a helper, narrowed by the caller
    "GET /builder/owned-inline",         # session.exec(builder(...)) directly
    "GET /conditional/narrowing",        # extra filter on one path keeps the common owner filter
    "GET /count/owned",                  # select(func.count()).select_from(Model).where(...)
    "POST /write/create-owned",          # Model.model_validate(..., update={owner}) + add
    "POST /write/create-owned-attr",     # Model.model_validate(...); obj.owner_id = user.id; add
    "PATCH /write/bulk-owned",           # update(Model).where(owner).values(...)
    "GET /deep/checked/{doc_id}",        # owner check five helper calls down
]

NEGATIVE = [
    ("GET /conditional/python-and", "read"),
    ("GET /generic/any/{doc_id}", "read"),          # same helper shape, no owner column
    ("GET /generic/mode/{doc_id}", "read"),         # owner filter on one branch of a runtime switch
    ("GET /builder/all/{doc_id}", "read"),          # builder without the owner filter
    ("GET /conditional/owner-optional", "read"),    # owner filter added on one path only
    ("GET /conditional/branch-built", "read"),      # one branch builds the unscoped statement
    ("GET /count/all", "read"),                     # aggregate over every row
    ("POST /write/create-unowned", "create"),       # owner never set
    ("PUT /write/merge/{doc_id}", "update"),        # merge() is an upsert of an arbitrary row
    ("DELETE /write/delete-untracked/{doc_id}", "delete"),  # delete of an object never checked
    ("PATCH /write/bulk-all", "update"),            # update without a where
    ("GET /deep/unchecked/{doc_id}", "read"),       # the same five-deep chain without the check
    ("POST /write/create-owner-overwritten/{owner_id}", "create"),  # owner reassigned from the request
]


@pytest.mark.parametrize("key", POSITIVE)
def test_authorized_idiom_is_safe(kernel, key):
    res = kernel[key]
    assert res.verdict == "safe", [(e.effect.kind, e.verdict) for e in res.effects]
    assert res.effects and all(e.verdict == "safe" for e in res.effects)
    assert not [o for o in res.endpoint.opaque if o.may_have_effects]
    assert res.provenance == {}


@pytest.mark.parametrize("key,kind", NEGATIVE)
def test_unauthorized_twin_is_never_green(kernel, key, kind):
    res = kernel[key]
    assert res.verdict in ("violation", "possible_violation")
    assert any(e.effect.kind == kind and e.effect.resource == "Doc" and e.verdict != "safe"
               for e in res.effects), [(e.effect.kind, e.verdict) for e in res.effects]


def test_recursion_is_cut_not_followed_forever(kernel):
    res = kernel["GET /deep/recursive/{doc_id}"]
    assert res.verdict not in GREEN
    assert any(o.reason == "recursion_or_depth_limit" for o in res.endpoint.opaque)


def test_owner_filter_reaches_the_effect_through_the_parametric_helper(kernel):
    read = kernel["GET /generic/owned/{doc_id}"].effects[0].effect
    assert read.resource == "Doc"                     # `model` resolved to the caller's class
    assert {"eq": [{"field": "owner_id"}, {"principal": "id"}]} in read.selector["and"]
    assert {"eq": [{"field": "id"}, {"param": "doc_id"}]} in read.selector["and"]


def test_filter_present_on_only_one_path_is_not_in_the_selector(kernel):
    for key in ("GET /conditional/owner-optional", "GET /conditional/branch-built",
                "GET /generic/mode/{doc_id}"):
        read = kernel[key].effects[0].effect
        assert "principal" not in str(read.selector) and "principal" not in str(read.guards), key


def test_merge_is_modeled_as_create_and_unscoped_update(kernel):
    effects = {(e.effect.kind, e.verdict) for e in kernel["PUT /write/merge/{doc_id}"].effects}
    assert ("update", "violation") in effects and ("create", "safe") in effects


def test_nothing_unauthorized_is_green(kernel):
    green = sorted(k for k, r in kernel.items() if r.verdict in GREEN)
    assert green == sorted(POSITIVE)
