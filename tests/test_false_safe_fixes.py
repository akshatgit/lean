"""Two former false-SAFE paths.

1. multi_row_guard: a guard from `if COND: raise` constrains only the row whose fields it
   tests.  Mixed-row conditions are split per row where they are conjunctions and dropped
   where they are not.
2. principal_dep_effect: a dependency taken for the caller because of its NAME is opened;
   what its body reads or writes is checked, and an unreadable body blocks SAFE.
"""
from pathlib import Path

import pytest

from keyhole.adapters import FastAPISQLAlchemyAdapter
from keyhole.adapters.fastapi_sqla import _FieldTerm, _field_rows
from keyhole.checker import check_endpoints
from keyhole.policy import load_policy
from keyhole.summaries import load_summaries

FIXTURES = Path(__file__).parent / "fixtures"
PROVEN = {"safe", "safe_assumed", "no_effects"}


def scan(name: str):
    path = FIXTURES / name
    policy = load_policy(path / "keyhole.policy.yaml")
    endpoints = FastAPISQLAlchemyAdapter().extract(path, load_summaries(path), policy=policy)
    return {r.endpoint.key: r for r in check_endpoints(endpoints, policy)}


@pytest.fixture(scope="module")
def rows():
    return scan("multi_row_guard")


@pytest.fixture(scope="module")
def deps():
    return scan("principal_dep_effect")


def verdicts(res, resource, kind="read"):
    return [e.verdict for e in res.effects if e.effect.resource == resource and e.effect.kind == kind]


# ------------------------------------------------------------------ 1. multi-row guards

@pytest.mark.parametrize("key", [
    "GET /or-denial/{doc_id}/{folder_id}",     # if doc.owner_id != user.id or folder.archived: raise
    "GET /not-and/{doc_id}/{folder_id}",       # if not (doc.owner_id == user.id and not folder.archived)
    "GET /helper/{doc_id}/{folder_id}",        # the same denial inside a helper taking both rows
])
def test_guard_on_one_row_does_not_authorize_the_other(rows, key):
    res = rows[key]
    assert res.verdict == "violation"
    assert verdicts(res, "Doc") == ["safe"]          # the row that IS owner-checked
    assert verdicts(res, "Folder") == ["violation"]  # the row that is not
    folder = next(e.effect for e in res.effects if e.effect.resource == "Folder")
    assert "principal" not in str(folder.guards), folder.guards


def test_cross_row_disjunction_is_attached_to_no_row(rows):
    # passes when EITHER row is owned: neither read is authorized by it
    res = rows["GET /either-owned/{doc_id}/{folder_id}"]
    assert res.verdict == "violation"
    assert verdicts(res, "Doc") == ["violation"] and verdicts(res, "Folder") == ["violation"]
    assert all(e.effect.guards == [] for e in res.effects)
    assert any("cross-row guard dropped" in c.expression for c in res.endpoint.unmodeled_checks)


def test_field_alias_guards_its_own_row_only(rows):
    res = rows["GET /alias/{doc_id}/{folder_id}"]
    assert res.verdict == "violation"
    assert verdicts(res, "Doc") == ["safe"] and verdicts(res, "Folder") == ["violation"]


def test_field_alias_does_not_follow_a_rebound_variable(rows):
    res = rows["GET /alias-rebound/{doc_id}/{other_id}"]
    assert res.verdict == "violation"
    assert "safe" not in verdicts(res, "Doc")


def test_comparison_between_two_rows_proves_nothing(rows):
    res = rows["GET /cross-compare/{doc_id}/{folder_id}"]
    assert res.verdict == "violation"
    assert verdicts(res, "Folder") == ["safe"] and verdicts(res, "Doc") == ["violation"]


def test_class_attribute_in_a_condition_names_no_row(rows):
    res = rows["GET /class-attr/{doc_id}"]
    assert res.verdict == "violation"
    assert all(e.effect.guards == [] for e in res.effects)


def test_field_of_another_row_is_not_a_column_of_the_selected_row(rows):
    res = rows["GET /foreign-selector/{folder_id}"]
    assert res.verdict not in PROVEN
    for e in res.effects:
        if e.effect.resource == "Doc":
            assert e.effect.selector is True     # widened, not `row.owner_id == row.owner_id`
            assert e.verdict != "safe"


@pytest.mark.parametrize("key", [
    "GET /both-checked/{doc_id}/{folder_id}",
    "GET /both-checked-not-and/{doc_id}/{folder_id}",
    "GET /alias-same-row/{doc_id}",
])
def test_genuinely_checked_rows_stay_safe(rows, key):
    res = rows[key]
    assert res.verdict == "safe"
    assert all(e.verdict == "safe" for e in res.effects)


def test_only_the_three_controls_are_safe(rows):
    assert sorted(k for k, r in rows.items() if r.verdict in PROVEN) == sorted([
        "GET /both-checked/{doc_id}/{folder_id}",
        "GET /both-checked-not-and/{doc_id}/{folder_id}",
        "GET /alias-same-row/{doc_id}",
    ])


def test_field_term_provenance_helpers():
    doc, folder = _FieldTerm("owner_id", "doc"), _FieldTerm("owner_id", "folder")
    assert doc == {"field": "owner_id"} and {"field": "owner_id"} == doc   # serialises as AIR
    assert doc != folder                                                 # but rows differ
    assert _field_rows({"or": [{"eq": [doc, {"principal": "id"}]}, {"eq": [folder, {"const": "x"}]}]}) \
        == {"doc", "folder"}
    assert _field_rows({"eq": [{"field": "id"}, {"param": "x"}]}) == {"?"}
    assert _field_rows({"eq": [{"param": "a"}, {"principal": "id"}]}) == set()


# ------------------------------------------------------------------ 2. name-matched principals

def test_resource_loader_named_like_a_principal_is_a_violation(deps):
    # `doc: Doc = Depends(get_doc_for_user)` loads an arbitrary Doc with no check
    res = deps["GET /loader-as-principal/{doc_id}"]
    assert res.verdict == "violation"
    assert "violation" in verdicts(res, "Doc")


def test_loader_that_depends_on_a_principal_is_not_the_caller(deps):
    res = deps["GET /loader-with-principal/{doc_id}"]
    assert res.verdict == "violation"
    assert res.endpoint.principal_binding is None        # demoted: it is a resource row
    assert verdicts(res, "Doc") == ["violation"]


def test_effect_hidden_inside_a_principal_dependency_is_checked(deps):
    res = deps["GET /hidden-read/{doc_id}"]
    assert res.verdict == "violation"
    assert res.endpoint.principal_binding == "user"      # still the principal
    assert sorted(verdicts(res, "Doc")) == ["safe", "violation"]   # endpoint's own read / the hidden one


def test_user_looked_up_by_request_id_is_not_the_caller(deps):
    res = deps["GET /profile/{user_id}"]
    assert res.verdict == "violation"
    assert verdicts(res, "User") == ["violation"]


def test_route_level_dependency_that_looks_like_auth_is_opened(deps):
    res = deps["GET /route-dep/{doc_id}"]
    assert res.verdict == "violation"
    assert verdicts(res, "Doc") == ["violation"]


def test_unreadable_name_matched_principal_blocks_safe(deps):
    res = deps["GET /unreadable/{doc_id}"]
    assert res.verdict == "unknown"
    assert any(o.reason == "principal_dependency_unverified" and o.may_have_effects
               for o in res.endpoint.opaque)


@pytest.mark.parametrize("key", ["GET /ok/{doc_id}", "GET /ok-active/{doc_id}"])
def test_real_principal_fetch_stays_the_principal_and_is_not_opaque(deps, key):
    res = deps[key]
    assert res.endpoint.principal_binding == "user"
    assert not [o for o in res.endpoint.opaque if o.may_have_effects]
    assert verdicts(res, "Doc") == ["safe"]
    assert verdicts(res, "User") == ["safe"]             # its own read is modeled, not hidden
    # ... but "this row is the caller" is an assumption, so the endpoint is not plain SAFE
    assert res.verdict == "safe_assumed"
    assert any("get_current_user" in a and "matched by name" in a for a in res.assumptions)


def test_checked_loader_is_safe_as_a_dependency_row(deps):
    res = deps["GET /owned-loader/{doc_id}"]
    assert res.endpoint.principal_binding is None
    assert verdicts(res, "Doc") == ["safe"]
    assert res.verdict == "safe_assumed"


def test_nothing_unauthorized_in_the_principal_fixture_is_proven(deps):
    assert sorted(k for k, r in deps.items() if r.verdict in PROVEN) == sorted([
        "GET /ok/{doc_id}", "GET /ok-active/{doc_id}", "GET /owned-loader/{doc_id}",
    ])
    assert not [k for k, r in deps.items() if r.verdict == "safe"]
