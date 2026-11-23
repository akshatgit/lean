"""Assumption-provenance set: no clean green verdict may rest on an assumption.

Every unproven claim the model depends on (a call declared irrelevant, a declared helper
guard, an unreviewed summary, an identity fact, an unconfirmed policy) has a stable id.
The ids are collected per endpoint as a set that only grows, travel through the purity
oracle's caches, and gate SAFE and no_effects.
"""
import ast
import json
from pathlib import Path

import pytest

from keyhole import air, report
from keyhole.adapters import FastAPISQLAlchemyAdapter
from keyhole.adapters import fastapi_sqla as adapter_module
from keyhole.checker import EndpointResult, _aggregate, check_endpoints
from keyhole.policy import load_policy
from keyhole.summaries import load_summaries

FIXTURES = Path(__file__).parent / "fixtures"
CLEAN_GREEN = {"safe", "no_effects"}


def scan_path(path: Path):
    policy = load_policy(path / "keyhole.policy.yaml")
    endpoints = FastAPISQLAlchemyAdapter().extract(path, load_summaries(path), policy=policy)
    return list(check_endpoints(endpoints, policy)), policy


@pytest.fixture(scope="module")
def prov():
    results, policy = scan_path(FIXTURES / "provenance")
    return {r.endpoint.key: r for r in results}, results, policy


def assert_amber(res, verdict, assumption_id):
    assert res.verdict == verdict
    assert res.verdict not in CLEAN_GREEN
    assert assumption_id in res.provenance, sorted(res.provenance)
    # nothing else explains the downgrade: no opaque, confirmed policy
    assert not [o for o in res.endpoint.opaque if o.may_have_effects]
    assert not [k for k in res.provenance if k.startswith("policy-unconfirmed:")]


# ---- the invariant itself ------------------------------------------------------------------

def test_no_clean_green_verdict_carries_an_assumption(prov):
    _, results, _ = prov
    for res in results:
        if res.verdict in CLEAN_GREEN:
            assert not res.provenance, (res.endpoint.key, res.provenance)
            assert not res.endpoint.assumptions


def test_controls_without_assumptions_stay_clean(prov):
    by_key, _, _ = prov
    assert by_key["GET /clean/{doc_id}"].verdict == "safe"
    assert by_key["GET /clean-ping"].verdict == "no_effects"
    assert by_key["GET /clean/{doc_id}"].provenance == {}


# ---- (a) green only because an unreadable call was declared irrelevant ----------------------

def test_ignored_call_in_statement_position_is_amber(prov):
    assert_amber(prov[0]["GET /ignored-statement/{doc_id}"], "safe_assumed", "ignore:record")


def test_ignored_call_in_a_skipped_position_is_amber(prov):
    # an `if` test: modeled as an expression-position call since move 2
    assert_amber(prov[0]["GET /ignored-in-condition/{doc_id}"], "safe_assumed", "ignore:lookup")


def test_no_effects_resting_on_a_declaration_is_not_clean(prov):
    res = prov[0]["GET /ignored-no-effects/{key}"]
    assert not res.effects
    assert_amber(res, "no_effects_assumed", "ignore:lookup")


def test_ignored_dependency_is_amber(prov):
    assert_amber(prov[0]["GET /ignored-dependency/{doc_id}"], "safe_assumed", "ignore:get_vendor_client")


# ---- (b) transitive: the oracle's cache carries the provenance ------------------------------

@pytest.mark.parametrize("key,verdict", [
    ("GET /transitive-first/{doc_id}", "safe_assumed"),    # closure computed here
    ("GET /transitive-cached/{doc_id}", "safe_assumed"),   # answered from the cache
    ("GET /transitive-no-effects", "no_effects_assumed"),  # cached, skipped position, no effects
    ("GET /transitive-cycle/{doc_id}", "safe_assumed"),    # declaration inside a recursion cycle
])
def test_declaration_reached_through_in_repo_helpers_is_amber(prov, key, verdict):
    assert_amber(prov[0][key], verdict, "declared-free:emit")


def test_oracle_returns_the_same_provenance_from_cache():
    path = FIXTURES / "provenance"
    policy = load_policy(path / "keyhole.policy.yaml")
    parsed = [(p, ast.parse(p.read_text())) for p in adapter_module._python_files(path)]
    index = adapter_module._RepoIndex(path, parsed, adapter_module.find_models(t for _, t in parsed), policy)
    purity = index.purity
    funcs = {q.rsplit(".", 1)[-1]: v for q, v in purity.toplevel_funcs.items()}
    expected = frozenset({"declared-free:emit"})
    for name in ("helper_a", "helper_b", "odd", "even", "helper_a", "even"):   # repeats hit the cache
        module, node = funcs[name]
        assert purity.function_free_deps(module, node) == (True, expected), name
    # every memoised entry stores its provenance next to the verdict
    assert all(isinstance(v, tuple) and len(v) == 2 for v in purity._free_cache.values())
    module, node = funcs["_owned"]
    assert purity.function_free_deps(module, node)[0] is False            # it reads the database
    module, node = funcs["get_session"]
    assert purity.function_free_deps(module, node) == (True, frozenset())  # proven: no declaration


# ---- (c) declared helper guard with no row argument -----------------------------------------

def test_global_helper_guard_is_amber(prov):
    res = prov[0]["GET /helper-guard/{doc_id}"]
    assert_amber(res, "safe_assumed", "helper-guard:ensure_document_access")
    assert [e.verdict for e in res.effects] == ["safe"]   # Lean proves it only WITH the declared guard


# ---- violations past a suppressed call ------------------------------------------------------

def test_violation_past_a_suppressed_call_is_a_lead(prov):
    res = prov[0]["GET /suppressed-then-idor/{doc_id}"]
    assert res.verdict == "possible_violation"
    assert any("ignore:record" in b for b in res.effects[0].blocking_calls)


# ---- union, never overwrite -----------------------------------------------------------------

def test_assumptions_from_several_sources_are_all_kept(tmp_path):
    (tmp_path / "keyhole.policy.yaml").write_text(
        "principal:\n  id: current_user.id\n"
        "helpers:\n  check_a: owner(owner_id)\n  check_b: owner(owner_id)\n"
        "adapter:\n  ignore_calls: [notify]\n"
        "resources:\n  Doc:\n    confirmed: false\n    read: owner(owner_id)\n")
    (tmp_path / "app.py").write_text(
        "import ext\nfrom fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n\n"
        "class Doc:\n    __tablename__ = 'docs'\n\n"
        "def get_current_user(): ...\n\ndef get_db(): ...\n\n"
        "@router.get('/d/{doc_id}')\n"
        "def read(doc_id: int, user=Depends(get_current_user), db=Depends(get_db)):\n"
        "    doc = db.get(Doc, doc_id)\n"
        "    ext.check_a(doc, user)\n"
        "    ext.check_b(doc, user)\n"      # a second helper on the same row must not replace the first
        "    ext.notify(doc_id)\n"
        "    return doc\n")
    (res,), _ = scan_path(tmp_path)
    assert {"helper-guard:check_a", "helper-guard:check_b", "ignore:notify",
            "policy-unconfirmed:Doc"} <= set(res.provenance)
    assert res.verdict == "safe_assumed"


# ---- checker: the gate ----------------------------------------------------------------------

def test_aggregate_gates_green_on_the_provenance_set():
    ep = air.Endpoint("GET", "/x", "f.py", 1)
    clean = EndpointResult(ep)
    assert _aggregate(clean, ep) == "no_effects"
    assumed = EndpointResult(ep, provenance={"ignore:f": "declared"})
    assert _aggregate(assumed, ep) == "no_effects_assumed"
    ep.opaque = [air.Opaque("g(...)", "source_unavailable", 1)]
    assert _aggregate(assumed, ep) == "unknown"            # incompleteness still dominates


def test_endpoint_json_carries_assumptions():
    ep = air.Endpoint("GET", "/x", "f.py", 1)
    ep.assumptions["ignore:f"] = "declared"
    assert ep.to_json()["assumptions"] == [{"id": "ignore:f", "reason": "declared"}]


# ---- reports surface the set ----------------------------------------------------------------

def test_reports_show_the_provenance_set(prov):
    _, results, policy = prov
    data = {item["endpoint"]: item for item in json.loads(report.json_report(results))}
    item = data["GET /transitive-cached/{doc_id}"]
    assert item["verdict"] == "safe_assumed"
    assert [p["id"] for p in item["provenance"]] == ["declared-free:emit"]
    assert item["air"]["assumptions"][0]["id"] == "declared-free:emit"
    assert data["GET /clean/{doc_id}"]["provenance"] == []
    text = report.text_report(results, policy)
    assert "assumes [declared-free:emit]" in text
    assert "assumes [helper-guard:ensure_document_access]" in text
    assert "NO EFFECTS (assumed)" in text
    stats = json.loads(report.stats_report(results))
    assert stats["verdict_counts"]["no_effects_assumed"] == 2
    assert stats["verdict_counts"]["safe"] == 1 and stats["verdict_counts"]["no_effects"] == 1
    report.html_report(results, policy)   # renders every verdict, including the new one


# ---- the shipped demo: confirmed policy, clean results stay clean ---------------------------

def test_demo_safe_endpoints_stay_clean_safe():
    results, _ = scan_path(FIXTURES.parent.parent / "examples" / "docs_app")
    by_key = {r.endpoint.key: r for r in results}
    for key in ("GET /api/v2/documents/{doc_id}", "GET /api/v3/documents/{doc_id}",
                "GET /api/v1/public/{doc_id}", "PUT /api/v1/documents/{doc_id}",
                "POST /api/v2/documents"):
        assert by_key[key].verdict == "safe", key
        assert by_key[key].provenance == {}
    # the one endpoint that uses an unreviewed summary carries its id
    assert "summary:storage.load_doc" in by_key["GET /api/v1/storage/{doc_id}"].provenance
    for res in results:
        if res.verdict in CLEAN_GREEN:
            assert not res.provenance
