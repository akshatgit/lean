from pathlib import Path

import pytest

from keyhole import air, report
from keyhole.adapters import FastAPISQLAlchemyAdapter
from keyhole.checker import check_endpoints
from keyhole.cli import main
from keyhole.policy import load_policy, parse_rule
from keyhole.summaries import load_summaries

DEMO = Path(__file__).resolve().parent.parent / "examples" / "docs_app"

EXPECTED = {
    "GET /api/v1/documents/{doc_id}": "violation",
    "GET /api/v2/documents/{doc_id}": "safe",
    "GET /api/v3/documents/{doc_id}": "safe",
    "GET /api/v1/public/{doc_id}": "safe",
    "PUT /api/v1/documents/{doc_id}": "safe",
    "DELETE /api/v1/documents/{doc_id}": "violation",
    "POST /api/v1/documents": "violation",
    "POST /api/v2/documents": "safe",
    "GET /api/v1/storage/{doc_id}": "violation",
    "GET /api/v1/export/{doc_id}": "unknown",
}


@pytest.fixture(scope="module")
def results():
    endpoints = FastAPISQLAlchemyAdapter().extract(DEMO, load_summaries(DEMO))
    policy = load_policy(DEMO / "keyhole.policy.yaml")
    return {r.endpoint.key: r for r in check_endpoints(endpoints, policy)}


@pytest.mark.parametrize("key,verdict", EXPECTED.items())
def test_demo_verdicts(results, key, verdict):
    assert results[key].verdict == verdict


def test_every_endpoint_found(results):
    assert set(results) == set(EXPECTED)


def test_storage_violation_is_marked_assumed(results):
    r = results["GET /api/v1/storage/{doc_id}"]
    assert any("storage.load_doc" in a for a in r.assumptions)


def test_air_for_vulnerable_endpoint(results):
    ep = results["GET /api/v1/documents/{doc_id}"].endpoint
    j = ep.to_json()
    assert j["principal"] == {"binding": "user", "via": "dependency"}
    assert j["params"]["doc_id"] == {"from": "path", "type": "int", "attacker_controlled": True}
    (eff,) = j["effects"]
    assert eff["kind"] == "read" and eff["resource"] == "Document"
    assert eff["selector"] == air.eq(air.fld("id"), air.param("doc_id"))


def test_witness_is_concrete(results):
    er = results["GET /api/v1/documents/{doc_id}"].effects[0]
    vals = {next(iter(t.items())): v for t, v in er.witness["values"]}
    assert vals[("field", "owner_id")] != vals[("principal", "id")]
    assert vals[("field", "id")] == vals[("param", "doc_id")]


def test_policy_parser():
    p = parse_rule("owner(owner_id) or (visibility == 'public' and member(folder_id))")
    assert p == air.or_(
        air.eq(air.fld("owner_id"), air.principal("id")),
        air.and_(air.eq(air.fld("visibility"), air.const("public")),
                 air.member("member", air.principal("id"), air.fld("folder_id"))))


def test_unconfirmed_policy_downgrades_safe(tmp_path):
    (tmp_path / "keyhole.policy.yaml").write_text(
        (DEMO / "keyhole.policy.yaml").read_text().replace("confirmed: true", "confirmed: false"))
    endpoints = FastAPISQLAlchemyAdapter().extract(DEMO, {})
    policy = load_policy(tmp_path / "keyhole.policy.yaml")
    res = {r.endpoint.key: r for r in check_endpoints(endpoints, policy)}
    assert res["GET /api/v2/documents/{doc_id}"].verdict == "safe_assumed"


def test_without_summary_storage_is_unknown():
    endpoints = FastAPISQLAlchemyAdapter().extract(DEMO, {})
    policy = load_policy(DEMO / "keyhole.policy.yaml")
    res = {r.endpoint.key: r for r in check_endpoints(endpoints, policy)}
    assert res["GET /api/v1/storage/{doc_id}"].verdict == "unknown"


def test_html_report_is_human_readable_and_filterable(results):
    policy = load_policy(DEMO / "keyhole.policy.yaml")
    page = report.html_report(list(results.values()), policy, title="Demo security report")

    assert "How to read this report" in page
    assert "Possible violation" in page
    assert "VIOLATION (modeled)" in page
    assert report.MODEL_TRUST_NOTICE in page
    assert "No modeled effects" in page
    assert 'id="filter-search"' in page
    assert 'id="filter-verdict"' in page
    assert 'id="filter-resource"' in page
    assert 'id="filter-review"' in page
    assert "Rows touched when" in page
    assert "Policy allows when" in page
    assert "GET /api/v1/documents/{doc_id}" in page


def test_cli_writes_html_report(tmp_path):
    output = tmp_path / "report.html"
    status = main(["scan", str(DEMO), "--format", "html", "--out", str(output)])

    assert status == 1
    assert output.read_text().startswith("<!doctype html>")
