"""keyhole.assumptions.yaml: schema, binding, fingerprints, review gating, worklist.

The file is the second human-controlled surface.  The tests are adversarial about the one
thing it must never do: turn an unreviewed, stale, misbound or refuted claim into green.
"""
import json
import shutil
from pathlib import Path

import pytest
import yaml

from keyhole import worklist
from keyhole.adapters import FastAPISQLAlchemyAdapter
from keyhole.assumptions import AssumptionError, load_assumptions, parse_entry
from keyhole.checker import check_endpoints
from keyhole.cli import main
from keyhole.policy import load_policy
from keyhole.summaries import load_summaries

FIXTURE = Path(__file__).parent / "fixtures" / "assumptions"
GREEN = {"safe", "safe_assumed", "no_effects", "no_effects_assumed"}
CLEAN = {"safe", "no_effects"}


def scan(path: Path, assumptions="keyhole.assumptions.yaml"):
    policy = load_policy(path / "keyhole.policy.yaml")
    entries = load_assumptions(path / assumptions if assumptions else None)
    adapter = FastAPISQLAlchemyAdapter()
    endpoints = adapter.extract(path, load_summaries(path), policy=policy, assumptions=entries)
    results = check_endpoints(endpoints, policy)
    return {r.endpoint.key: r for r in results}, entries, adapter, results


@pytest.fixture(scope="module")
def unreviewed():
    return scan(FIXTURE)


@pytest.fixture()
def repo(tmp_path):
    copy = tmp_path / "app"
    shutil.copytree(FIXTURE, copy)
    return copy


def review(repo: Path, *ids):
    for entry_id in ids:
        assert main(["review", str(repo), entry_id, "--by", "tester"]) == 0


def effect_opaque(res):
    return [o for o in res.endpoint.opaque if o.may_have_effects]


# ---- unreviewed entries: they apply, and everything they touch is amber ---------------------

def test_without_the_file_nothing_is_green():
    results, _, _, _ = scan(FIXTURE, assumptions=None)
    assert not [k for k, r in results.items() if r.verdict in GREEN]


def test_unreviewed_assumptions_never_give_clean_green(unreviewed):
    results, entries, _, _ = unreviewed
    assert all(e.status == "assumed" for e in entries.entries)
    for key, res in results.items():
        if res.verdict in CLEAN:
            assert not res.provenance, key
    assert results["GET /locator/owned/{doc_id}"].verdict == "safe_assumed"
    assert {"assume:A-LOCATOR-TYPE", "assume:A-LOCATOR-FX"} <= set(
        results["GET /locator/owned/{doc_id}"].provenance)


# (g) returns_type: the adapter analyses the REAL method body behind the locator
def test_returns_type_exposes_the_unguarded_read_behind_a_locator(unreviewed):
    res = unreviewed[0]["GET /locator/any/{doc_id}"]
    assert res.verdict in ("violation", "possible_violation")
    assert any(e.effect.resource == "Doc" and e.effect.kind == "read" and e.verdict != "safe"
               for e in res.effects)
    assert not effect_opaque(res)            # the method body was read, not assumed


def test_returns_type_keeps_the_real_guard_of_the_resolved_method(unreviewed):
    res = unreviewed[0]["GET /locator/owned/{doc_id}"]
    assert [e.verdict for e in res.effects] == ["safe"]
    assert "principal" in str(res.effects[0].effect.guards)


# (e) effects: [] refused where the call is handed the means to touch data
def test_irrelevance_applies_only_at_harmless_call_sites(unreviewed):
    results = unreviewed[0]
    scalars = results["GET /emit/scalars/{doc_id}"]
    assert scalars.verdict == "safe_assumed" and "assume:A-EMIT" in scalars.provenance
    handed_session = results["GET /emit/session/{doc_id}"]
    assert handed_session.verdict == "unknown"
    assert any("vendor.emit" in o.call for o in effect_opaque(handed_session))
    assert "assume:A-EMIT" not in handed_session.provenance


def test_positive_effect_model_is_checked_not_trusted(unreviewed):
    # `effects: [read Doc by id]`: the declared read is emitted and Lean checks it
    res = unreviewed[0]["GET /audit/{doc_id}"]
    assert res.verdict in ("violation", "possible_violation")
    read = res.effects[0].effect
    assert (read.kind, read.resource) == ("read", "Doc")
    assert read.selector == {"eq": [{"field": "id"}, {"param": "doc_id"}]}


# (f) ensures: a guard only when the helper was really given the caller
def test_ensures_applies_only_with_the_principal(unreviewed):
    results = unreviewed[0]
    ok = results["GET /ensures/principal/{doc_id}"]
    assert ok.verdict == "safe_assumed" and "assume:A-ENSURE-OWNER" in ok.provenance
    other = results["GET /ensures/other-user/{doc_id}/{other_id}"]
    assert other.verdict in ("violation", "possible_violation")
    assert "assume:A-ENSURE-OWNER" not in other.provenance
    assert all(e.effect.guards == [] for e in other.effects)


# (h) binding is by resolved identity
def test_entry_for_another_modules_namesake_never_binds(unreviewed):
    results, entries, _, _ = unreviewed
    assert entries.get("A-WRONG-MODULE").status == "assumed"          # it resolves ...
    assert not any("A-WRONG-MODULE" in key for res in results.values() for key in res.provenance)


def test_unresolvable_target_is_unbound_and_never_applies(repo):
    path = repo / "keyhole.assumptions.yaml"
    data = yaml.safe_load(path.read_text())
    for raw in data["assumptions"]:
        if raw["id"] == "A-ENSURE-OWNER":
            raw["target"]["symbol"] = "app.no_such_function"
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    results, entries, _, _ = scan(repo)
    assert entries.get("A-ENSURE-OWNER").status == "unbound"
    assert results["GET /ensures/principal/{doc_id}"].verdict == "violation"


def test_principal_claim_binds_the_dependency(unreviewed):
    res = unreviewed[0]["GET /actor/{doc_id}"]
    assert res.endpoint.principal_binding == "actor"
    assert res.verdict == "safe_assumed" and "assume:A-ACTOR" in res.provenance


def test_assumption_reached_through_the_oracle_cache_is_recorded(unreviewed):
    res = unreviewed[0]["GET /emit/transitive/{doc_id}"]
    assert res.verdict == "safe_assumed" and "assume:A-EMIT" in res.provenance


# ---- (a) review: digests match and the claim holds -> clean green is allowed ---------------

def test_reviewed_assumptions_allow_clean_green(repo):
    review(repo, "A-LOCATOR-TYPE", "A-LOCATOR-FX", "A-ENSURE-OWNER", "A-EMIT")
    results, entries, _, _ = scan(repo)
    assert entries.get("A-LOCATOR-TYPE").status == "reviewed"
    owned = results["GET /locator/owned/{doc_id}"]
    assert owned.verdict == "safe"
    assert {"reviewed:A-LOCATOR-TYPE", "reviewed:A-LOCATOR-FX"} <= set(owned.provenance)   # still shown
    assert results["GET /ensures/principal/{doc_id}"].verdict == "safe"
    assert results["GET /emit/scalars/{doc_id}"].verdict == "safe"
    # a reviewed fact does not soften a finding either: the unguarded read is now a VIOLATION
    assert results["GET /locator/any/{doc_id}"].verdict == "violation"
    # and review changes nothing about where a claim may apply
    assert results["GET /emit/session/{doc_id}"].verdict == "unknown"
    assert results["GET /ensures/other-user/{doc_id}/{other_id}"].verdict in ("violation", "possible_violation")


# ---- (b) the helper body changes after review -> stale -> amber ----------------------------

def test_target_edited_after_review_is_stale(repo):
    review(repo, "A-LOCATOR-TYPE", "A-LOCATOR-FX")
    app = repo / "app.py"
    app.write_text(app.read_text().replace(
        '    return get_service("docs")', '    return get_service("docs" + "")'))
    results, entries, _, _ = scan(repo)
    entry = entries.get("A-LOCATOR-TYPE")
    assert entry.status == "stale" and "target changed after review" in entry.reason
    owned = results["GET /locator/owned/{doc_id}"]
    assert owned.verdict == "safe_assumed"
    assert "assume:A-LOCATOR-TYPE" in owned.provenance
    assert "stale" in owned.provenance["assume:A-LOCATOR-TYPE"]


def test_comment_or_docstring_edit_does_not_stale_a_review(repo):
    review(repo, "A-ENSURE-OWNER")
    app = repo / "app.py"
    app.write_text(app.read_text().replace(
        "    if not _same(owner_id, user.id):", "    # reviewed 2026\n    if not _same(owner_id, user.id):"))
    results, entries, _, _ = scan(repo)
    assert entries.get("A-ENSURE-OWNER").status == "reviewed"
    assert results["GET /ensures/principal/{doc_id}"].verdict == "safe"


# ---- (c) the claim changes after review -> digest mismatch -> amber ------------------------

def test_claim_edited_after_review_is_unreviewed(repo):
    review(repo, "A-ENSURE-OWNER")
    path = repo / "keyhole.assumptions.yaml"
    data = yaml.safe_load(path.read_text())
    for raw in data["assumptions"]:
        if raw["id"] == "A-ENSURE-OWNER":
            raw["claim"]["ensures"]["guard"] = {"and": [raw["claim"]["ensures"]["guard"]]}
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    results, entries, _, _ = scan(repo)
    entry = entries.get("A-ENSURE-OWNER")
    assert entry.status == "assumed" and "claim edited after review" in entry.reason
    assert results["GET /ensures/principal/{doc_id}"].verdict == "safe_assumed"


def test_a_review_block_cannot_be_forged_by_writing_one(repo):
    path = repo / "keyhole.assumptions.yaml"
    data = yaml.safe_load(path.read_text())
    for raw in data["assumptions"]:
        raw["review"] = {"by": "llm", "at": "now", "entry_sha256": "0" * 64, "target_sha256": "0" * 64}
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    results, entries, _, _ = scan(repo)
    assert not [e for e in entries.entries if e.status == "reviewed"]
    assert not [k for k, r in results.items() if r.verdict in CLEAN and r.provenance]
    assert results["GET /locator/owned/{doc_id}"].verdict == "safe_assumed"


# ---- (d) the database kernel can never be assumed ------------------------------------------

BASE = {"claim": {"effects": []}, "evidence": {"note": "x"}}


@pytest.mark.parametrize("target", [
    {"symbol": "sqlmodel.ext.asyncio.session.AsyncSession.exec"},
    {"symbol": "sqlalchemy.orm.Session.execute"},
    {"symbol": "sqlmodel.select"},
    {"symbol": "app.session.add"},
    {"site": {"function": "app.emit_session", "callee": "session.exec"}},
    {"site": {"function": "app.Repo.load", "callee": "self.session.get"}},
    {"site": {"function": "app.emit_session", "callee": "select"}},
])
def test_kernel_targets_are_load_errors(target):
    with pytest.raises(AssumptionError):
        parse_entry({"id": "K", "target": target, **BASE})


def test_assumption_never_applies_to_a_call_on_the_session(repo):
    # a site entry spelled so that it passes the loader but names a call on the db handle
    (repo / "extra.py").write_text(
        "from fastapi import APIRouter, Depends\nfrom app import Doc, get_session, get_current_user\n"
        "router = APIRouter()\n\n"
        "@router.get('/raw/{doc_id}')\n"
        "async def raw(doc_id: int, handle=Depends(get_session), user=Depends(get_current_user)):\n"
        "    return await handle.get(Doc, doc_id)\n")
    path = repo / "keyhole.assumptions.yaml"
    data = yaml.safe_load(path.read_text())
    data["assumptions"].append({"id": "A-RAW", "target": {"site": {"function": "extra.raw", "callee": "handle.get"}},
                                "claim": {"effects": []}, "evidence": {"note": "x"}})
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    results, _, _, _ = scan(repo)
    res = results["GET /raw/{doc_id}"]
    assert res.verdict == "violation"                      # the read is modeled, not suppressed
    assert "assume:A-RAW" not in res.provenance


# ---- strict loader -------------------------------------------------------------------------

@pytest.mark.parametrize("mutate,message", [
    (lambda e: e.update(surprise=1), "unknown key"),
    (lambda e: e["claim"].update(returns_type="a.B"), "exactly one claim"),
    (lambda e: e.update(claim={"returns_truth_of": {}}), "unknown claim kind"),
    (lambda e: e.update(claim={}), "exactly one claim"),
    (lambda e: e["target"].update(symbol="ensure_owner"), "fully qualified"),      # (h) short name
    (lambda e: e["target"].update(site={"function": "a.b", "callee": "c"}), "exactly one of"),
    (lambda e: e.update(claim={"effects": [{"kind": "peek", "resource": "Doc"}]}), "effect kind"),
    (lambda e: e.update(claim={"ensures": {"row": {"param": "x"}}}), "guard"),
    (lambda e: e.update(claim={"principal": False}), "principal must be true"),
    (lambda e: e.update(review={"by": "me"}), "review needs"),
])
def test_loader_rejects_malformed_entries(mutate, message):
    entry = {"id": "X", "target": {"symbol": "app.ensure_owner"}, "claim": {"effects": []}}
    mutate(entry)
    with pytest.raises(AssumptionError, match=message):
        parse_entry(entry)


def test_loader_rejects_wrong_schema_duplicates_and_double_claims(tmp_path):
    path = tmp_path / "a.yaml"
    path.write_text("schema: 2\nassumptions: []\n")
    with pytest.raises(AssumptionError, match="schema"):
        load_assumptions(path)
    entry = {"id": "X", "target": {"symbol": "app.f"}, "claim": {"effects": []}}
    path.write_text(yaml.safe_dump({"schema": 1, "assumptions": [entry, entry]}))
    with pytest.raises(AssumptionError, match="duplicate"):
        load_assumptions(path)
    path.write_text(yaml.safe_dump({"schema": 1, "assumptions": [entry, {**entry, "id": "Y"}]}))
    with pytest.raises(AssumptionError, match="second effects claim"):
        load_assumptions(path)
    path.write_text(yaml.safe_dump({"schema": 1, "assumptions": [], "extra": 1}))
    with pytest.raises(AssumptionError, match="top-level"):
        load_assumptions(path)


def test_bare_on_key_is_reported_clearly():
    with pytest.raises(AssumptionError, match="row"):
        parse_entry(yaml.safe_load(
            "id: X\ntarget: {symbol: app.f}\nclaim:\n  ensures:\n    on: {param: a}\n    guard: {eq: [{field: a}, {const: 1}]}\n"))


# ---- worklist and migration ----------------------------------------------------------------

def test_worklist_ranks_targets_by_endpoints_freed():
    _, _, adapter, results = scan(FIXTURE, assumptions=None)
    data = worklist.build(results, adapter.last_index.purity, top=10)
    by_target = {item["target"]: item for item in data["targets"]}
    assert data["blocked_endpoints"] == sum(r.verdict == "unknown" for r in results)
    combined = worklist.build(results, adapter.last_index.purity, include_possible=True)
    assert combined["blocked_by_verdict"] == {"unknown": data["blocked_endpoints"], "possible_violation": 1}
    assert any("GET /actor/{doc_id}" in ep for item in combined["targets"] for ep in item["blocked_endpoints"])
    assert "1 POSSIBLE VIOLATION" in worklist.text(combined)
    assert by_target["vendor.emit"]["kind"] == "external"
    assert by_target["vendor.emit"]["sole_blocker_of"] >= 2
    # an opaque deep inside the locator is also covered by an assumption on the locator
    assert by_target["app.get_doc_service"]["kind"] == "repository"
    assert by_target["app.get_doc_service"]["endpoints_present"] == 2
    cover = data["greedy_cover"]
    assert cover[0]["frees"] >= 1 and cover[-1]["freed_total"] == sum(step["frees"] for step in cover)
    assert json.loads(worklist.dumps(data))["tail"]["after_steps"] == len(cover)
    assert "Greedy cover" in worklist.text(data)
    packs = worklist.prompt_packs(data, adapter.last_index.purity)
    pack = next(p for p in packs if p["target"] == "app.get_doc_service")
    assert "def get_doc_service" in pack["source_excerpt"] and pack["blocked_endpoints"]
    assert worklist.build(results, adapter.last_index.purity) == worklist.build(results, adapter.last_index.purity)


def test_migrate_writes_loadable_unreviewed_entries(tmp_path, capsys):
    source = Path(__file__).parent / "fixtures" / "provenance"
    out = tmp_path / "migrated.yaml"
    assert main(["migrate-assumptions", str(source), "--out", str(out)]) == 0
    migrated = load_assumptions(out)
    assert migrated.entries and all(e.kind == "effects" and e.claim == [] and e.review is None
                                    for e in migrated.entries)
    assert "not migrated - helpers: ensure_document_access" in out.read_text()


def test_cli_scan_picks_up_the_file_and_worklist_runs(repo, capsys):
    assert main(["scan", str(repo), "--format", "json"]) in (0, 1)
    data = {item["endpoint"]: item for item in json.loads(capsys.readouterr().out)}
    assert data["GET /emit/scalars/{doc_id}"]["verdict"] == "safe_assumed"
    assert [p["id"] for p in data["GET /emit/scalars/{doc_id}"]["provenance"]] == ["assume:A-EMIT"]
    assert main(["worklist", str(repo), "--format", "json", "--prompt-pack", str(repo / "packs")]) == 0
    assert json.loads(capsys.readouterr().out)["blocked_endpoints"] >= 1


def test_scan_refuses_verdicts_when_a_source_file_cannot_be_parsed(repo):
    (repo / "dependency.py").write_text("def invalid(:\n")
    output = repo / "report.json"
    with pytest.raises(SystemExit, match=r"dependency\.py:1 with Python"):
        main(["scan", str(repo), "--format", "json", "--out", str(output)])
    assert not output.exists()
