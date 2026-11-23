"""Move 2: generic SQLAlchemy/SQLModel kernel idioms.

Each capability is tested twice: a positive route where the authorization really is in
the code (must be SAFE) and a negative twin where it is not (must be a violation or a
lead, never green).  A capability that only had the positive half could be producing
SAFE for the wrong reason.
"""
import json
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
    "POST /write/create-owner-last",
    "GET /conditional/imported-and",
    "GET /owned-projection",
    "GET /optional-checked/{doc_id}",
    "GET /conditional/partial-sql-and",
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
    ("GET /conditional/converted-owner", "read"),
    ("POST /write/create-owner-first", "create"),
    ("GET /conditional/local-and", "read"),
    ("GET /conditional/local-col", "read"),
    ("GET /optional-bypassed/{doc_id}", "read"),
    ("GET /conditional/partial-sql-or", "read"),
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


def test_deep_read_is_displayed_under_direct_helper(kernel):
    from keyhole.report import _html_helper_trace

    res = kernel["GET /deep/checked/{doc_id}"]
    trace = _html_helper_trace(res)
    assert trace.count("<summary>") == 1
    assert "_level1_checked" in trace
    assert "1 modeled effects" in trace
    assert "read Doc" in trace


def test_filter_conversion_requires_a_known_result(kernel):
    known = kernel["GET /conditional/converted-literal"].effects[0].effect
    assert known.selector == {"eq": [{"field": "id"}, {"const": "7"}]}
    assert kernel["GET /conditional/shadowed-conversion"].effects[0].effect.selector is True


def test_nullable_query_filters_require_a_column_on_the_selected_table(kernel, tmp_path):
    template = (FIXTURE / "keyhole.policy.yaml").read_text()
    config = tmp_path / "shared.yaml"
    config.write_text(template.replace("read: owner(owner_id)", "read: owner(owner_id) or is_null(owner_id)"))
    keys = ["GET /shared-docs", "GET /shared-peer-filter"]
    shared, other = check_endpoints([kernel[key].endpoint for key in keys], load_policy(config))
    assert shared.verdict == "safe"
    assert other.effects[0].effect.selector is True
    assert other.verdict == "possible_violation"
    assert kernel["GET /null-owner-only"].effects[0].effect.selector == {
        "eq": [{"field": "owner_id"}, {"const": None}]
    }


def test_session_get_uses_an_inherited_key_and_widens_composite_lookups(kernel):
    assert kernel["GET /ticket/{number}"].effects[0].effect.selector == {
        "eq": [{"field": "ticket_number"}, {"param": "number"}]
    }
    pair = kernel["GET /pair/{number}"]
    assert pair.effects[0].effect.selector is True
    assert any("primary key" in c.expression for c in pair.endpoint.unmodeled_checks)


@pytest.mark.parametrize("route", ["GET /mixed-projection", "GET /untyped-projection"])
def test_comprehension_requires_a_fresh_result_from_a_known_session(kernel, route):
    assert kernel[route].verdict == "unknown"


def test_branch_specific_filters_preserve_owned_or_shared_rows(kernel, tmp_path):
    res = kernel["GET /conditional/owned-or-shared"]
    assert res.verdict in {"possible_violation", "violation"}  # owner-only policy
    config = tmp_path / "shared.yaml"
    template = (FIXTURE / "keyhole.policy.yaml").read_text()
    config.write_text(template.replace("read: owner(owner_id)", "read: owner(owner_id) or is_null(owner_id)"))
    checked, = check_endpoints([res.endpoint], load_policy(config))
    assert checked.verdict == "safe"


def test_many_independent_filter_choices_widen_with_review_note(tmp_path):
    source = (FIXTURE / "app.py").read_text()
    choices = "".join(
        f"    if flags[{i}]:\n        stmt = stmt.where(Doc.title == 'a{i}')\n"
        f"    else:\n        stmt = stmt.where(Doc.title == 'b{i}')\n"
        for i in range(10)
    )
    (tmp_path / "app.py").write_text(source + '\n@router.get("/many-choices")\n'
        'async def many_choices(flags: list, session=Depends(get_session)):\n'
        '    stmt = select(Doc)\n' + choices + '    return (await session.exec(stmt)).all()\n')
    policy = load_policy(FIXTURE / "keyhole.policy.yaml")
    endpoints = FastAPISQLAlchemyAdapter().extract(tmp_path, {}, policy=policy)
    endpoint = next(ep for ep in endpoints if ep.path == "/many-choices")
    assert any("DNF limit" in check.expression for check in endpoint.unmodeled_checks)


def test_matching_primary_key_to_caller_does_not_prove_ownership_of_other_field(kernel, tmp_path):
    config = tmp_path / "policy.yaml"
    config.write_text("resources:\n  Ticket:\n    confirmed: true\n    read: owner(id)\n")
    result, = check_endpoints([kernel["GET /my-ticket"].endpoint], load_policy(config))
    assert result.verdict == "violation"


@pytest.mark.parametrize("allow,expected", [
    ("owner(owner_id)", "violation"),
    ("owner(owner_id) or is_null(owner_id)", "safe"),
    ("owner(owner_id) or owner_id == 'n:'", "violation"),
    ("owner(owner_id) or owner_id == 'None'", "violation"),
])
def test_nullable_ownership_guard_is_checked_against_policy(kernel, tmp_path, allow, expected):
    endpoint = kernel["GET /nullable-owner/{doc_id}"].endpoint
    config = tmp_path / "policy.yaml"
    template = (FIXTURE / "keyhole.policy.yaml").read_text()
    config.write_text(template.replace("read: owner(owner_id)", "read: " + json.dumps(allow)))
    result, = check_endpoints([endpoint], load_policy(config))
    assert result.verdict == expected
    if expected == "violation":
        assert [{"field": "owner_id"}, None] in result.effects[0].witness["values"]


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
