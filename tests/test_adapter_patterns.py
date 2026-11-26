import json
import shutil
from pathlib import Path

import pytest

from keyhole import report
from keyhole.adapters import FastAPISQLAlchemyAdapter
from keyhole.checker import check_endpoints
from keyhole.cli import main
from keyhole.policy import load_policy
from keyhole.summaries import load_summaries

FIXTURES = Path(__file__).parent / "fixtures"
SAFE_FIXTURES = [
    "aliased_principal",
    "incremental_stmt",
    "helper_other_module",
    "non_auth_size_check",
    "logger_response",
]


def scan(path: Path, *, include_tests: bool = False):
    policy = load_policy(path / "keyhole.policy.yaml")
    endpoints = FastAPISQLAlchemyAdapter().extract(
        path,
        load_summaries(path),
        include_tests=include_tests,
        policy=policy,
    )
    return check_endpoints(endpoints, policy)


@pytest.mark.parametrize("name", SAFE_FIXTURES)
def test_supported_pattern_is_safe(name):
    (result,) = scan(FIXTURES / name)
    assert result.verdict == "safe"
    assert not result.endpoint.opaque


def test_aliased_principal_is_resolved_across_imports():
    (result,) = scan(FIXTURES / "aliased_principal")
    assert result.endpoint.principal_binding == "current_user"
    assert "current_user" not in result.endpoint.params


def test_unsupported_non_auth_check_is_dropped_not_opaque():
    (result,) = scan(FIXTURES / "non_auth_size_check")
    assert result.verdict == "safe"
    assert not result.endpoint.opaque
    assert any("limit > 100" in check.expression for check in result.endpoint.unmodeled_checks)


def test_opaque_permission_helper_makes_violation_possible():
    (result,) = scan(FIXTURES / "opaque_permission")
    assert result.verdict == "possible_violation"
    assert result.effects[0].blocking_calls == ["permissions.ensure_document_access(...)"]


def test_trusted_helper_policy_is_an_explicit_assumption(tmp_path):
    fixture = tmp_path / "app"
    shutil.copytree(FIXTURES / "opaque_permission", fixture)
    policy_path = fixture / "keyhole.policy.yaml"
    policy_path.write_text(
        policy_path.read_text()
        + "\nhelpers:\n  ensure_document_access: owner(owner_id)\n"
    )
    (result,) = scan(fixture)
    assert result.verdict == "safe_assumed"
    assert any("ensure_document_access" in item for item in result.assumptions)


def test_test_code_is_skipped_unless_requested():
    fixture = FIXTURES / "test_filter"
    assert [r.endpoint.key for r in scan(fixture)] == ["GET /production"]
    assert {r.endpoint.key for r in scan(fixture, include_tests=True)} == {
        "GET /production",
        "GET /test-only",
    }


MUTATIONS = {
    "aliased_principal": (
        "app.py",
        "    if document.owner_id != current_user.id:\n        raise HTTPException(404)\n",
    ),
    "incremental_stmt": (
        "app.py",
        "    stmt = stmt.where(Document.owner_id == user.id)\n",
    ),
    "helper_other_module": (
        "helpers.py",
        "    if document.owner_id != user.id:\n        raise HTTPException(404)\n",
    ),
    "non_auth_size_check": (
        "app.py",
        "    if document.owner_id != user.id:\n        raise HTTPException(404)\n",
    ),
    "logger_response": (
        "app.py",
        ", Document.owner_id == user.id",
    ),
}


@pytest.mark.parametrize("name", SAFE_FIXTURES)
def test_removing_owner_check_can_never_stay_safe(name, tmp_path):
    fixture = tmp_path / name
    shutil.copytree(FIXTURES / name, fixture)
    relative, snippet = MUTATIONS[name]
    source = fixture / relative
    original = source.read_text()
    assert snippet in original
    source.write_text(original.replace(snippet, "", 1))

    (result,) = scan(fixture)
    assert result.verdict in {"violation", "possible_violation"}


def test_fail_on_possible_is_opt_in(tmp_path):
    fixture = FIXTURES / "opaque_permission"
    output = tmp_path / "report.json"
    assert main(["scan", str(fixture), "--format", "json", "--out", str(output)]) == 0
    assert main([
        "scan", str(fixture), "--format", "json", "--out", str(output),
        "--fail-on", "possible",
    ]) == 1


def test_stats_are_machine_readable():
    results = scan(FIXTURES.parent.parent / "examples" / "docs_app")
    stats = json.loads(report.stats_report(results))
    assert stats["endpoints"] == 10
    assert stats["verdict_counts"]["unknown"] == 1
    assert stats["unknown_causes"]["by_reason"]["source_unavailable"] >= 1


def test_configured_superuser_dependency_guards_helper_effects(tmp_path):
    (tmp_path / "models.py").write_text(
        'class Document:\n    __tablename__ = "documents"\n\nclass User:\n    pass\n'
    )
    (tmp_path / "helpers.py").write_text(
        "from models import Document\n\n"
        "def all_documents(session):\n"
        "    return session.query(Document).all()\n"
    )
    (tmp_path / "app.py").write_text(
        "from typing import Annotated\n"
        "from fastapi import APIRouter, Depends\n"
        "from helpers import all_documents\n"
        "from models import User\n\n"
        "router = APIRouter()\n\n"
        "def get_current_active_superuser(): pass\n"
        "def get_db(): pass\n\n"
        "@router.get('/documents')\n"
        "def read_all(admin: Annotated[User, Depends(get_current_active_superuser)], "
        "session=Depends(get_db)):\n"
        "    return all_documents(session)\n"
    )
    (tmp_path / "keyhole.policy.yaml").write_text(
        "principal:\n"
        "  id: current_user.id\n"
        "  bypass: current_user.is_superuser\n"
        "  superuser_dependencies: [get_current_active_superuser]\n"
        "resources:\n"
        "  Document:\n"
        "    confirmed: true\n"
        "    read: owner(owner_id)\n"
    )

    (result,) = scan(tmp_path)
    assert result.verdict == "safe_assumed"
    assert any("get_current_active_superuser" in item for item in result.assumptions)


@pytest.mark.parametrize(
    "endpoint",
    [
        "GET /conditional/{doc_id}",
        "GET /nested-raise/{doc_id}",
        "GET /caught/{doc_id}",
        "GET /loop/{doc_id}",
        "GET /finally/{doc_id}",
        "GET /early-return/{doc_id}",
    ],
)
def test_review_soundness_regressions_are_never_safe(endpoint):
    results = {result.endpoint.key: result for result in scan(FIXTURES / "soundness_review")}
    assert results[endpoint].verdict in {"violation", "possible_violation", "unknown"}


def test_unmodelled_denial_check_makes_violation_possible():
    results = {result.endpoint.key: result for result in scan(FIXTURES / "soundness_review")}
    result = results["GET /unresolved-denial/{doc_id}"]
    assert result.verdict == "possible_violation"
    assert any("unmodelled check" in call for call in result.effects[0].blocking_calls)
    assert not result.endpoint.opaque


def test_unresolved_result_used_in_response_is_opaque():
    results = {result.endpoint.key: result for result in scan(FIXTURES / "soundness_review")}
    result = results["GET /unresolved-return"]
    assert result.verdict == "unknown"
    assert any(item.reason == "unresolved_result_in_returned_response" for item in result.endpoint.opaque)


def test_row_only_helper_transfers_parameter_guard():
    results = {result.endpoint.key: result for result in scan(FIXTURES / "soundness_review")}
    result = results["GET /row-helper/{doc_id}"]
    assert result.verdict == "safe"
    assert not result.endpoint.opaque


def test_method_allowlist_is_receiver_aware():
    results = {result.endpoint.key: result for result in scan(FIXTURES / "receiver_allowlist")}
    assert results["GET /service/{doc_id}"].verdict != "safe"
    assert results["GET /dict/{doc_id}"].verdict == "safe"
    assert not results["GET /dict/{doc_id}"].endpoint.opaque


def test_router_and_security_authentication_sources():
    results = {result.endpoint.key: result for result in scan(FIXTURES / "router_auth")}
    router_auth = results["GET /router-auth/{doc_id}"].endpoint
    db_only = results["GET /db-only/{doc_id}"].endpoint
    security = results["GET /security/{doc_id}"].endpoint
    app_auth = results["GET /app-auth/{doc_id}"].endpoint
    included = results["GET /included/{doc_id}"].endpoint
    explicit = results["GET /explicit-included/{doc_id}"].endpoint
    assert router_auth.principal_via == "router"
    assert router_auth.principal_binding is None
    assert db_only.principal_via == "none"
    assert security.principal_via == "dependency"
    assert security.principal_binding == "current_user"
    assert app_auth.principal_via == "router"
    assert included.principal_via == "router"
    assert explicit.principal_via == "router"


VULNERABLE_OWNER_CHECK_VARIANTS = {
    "conditional": (
        "    if flag:\n"
        "        if document.owner_id != user.id:\n"
        "            raise HTTPException(404)\n"
    ),
    "caught": (
        "    try:\n"
        "        if document.owner_id != user.id:\n"
        "            raise HTTPException(404)\n"
        "    except Exception:\n"
        "        pass\n"
    ),
    "early_return": (
        "    if flag:\n"
        "        return document\n"
        "    if document.owner_id != user.id:\n"
        "        raise HTTPException(404)\n"
    ),
}


@pytest.mark.parametrize("name", SAFE_FIXTURES)
@pytest.mark.parametrize("variant", VULNERABLE_OWNER_CHECK_VARIANTS)
def test_safe_fixture_owner_check_mutations_are_never_safe(name, variant, tmp_path):
    fixture = tmp_path / name
    shutil.copytree(FIXTURES / name, fixture)
    (fixture / "app.py").write_text(
        "from fastapi import APIRouter, Depends, HTTPException\n"
        "from models import Document, User\n\n"
        "router = APIRouter()\n\n"
        "def get_current_user(): pass\n"
        "def get_db(): pass\n\n"
        "@router.get('/documents/{doc_id}')\n"
        "def read_document(doc_id: int, flag: bool, user: User = Depends(get_current_user), "
        "session=Depends(get_db)):\n"
        "    document = session.get(Document, doc_id)\n"
        f"{VULNERABLE_OWNER_CHECK_VARIANTS[variant]}"
        "    return document\n"
    )
    (result,) = scan(fixture)
    assert result.verdict in {"violation", "possible_violation", "unknown"}


def test_stats_path_is_written_alongside_report(tmp_path):
    fixture = FIXTURES / "opaque_permission"
    output = tmp_path / "report.json"
    stats = tmp_path / "stats.json"
    main([
        "scan", str(fixture), "--format", "json", "--out", str(output),
        "--stats", str(stats),
    ])
    assert isinstance(json.loads(output.read_text()), list)
    assert json.loads(stats.read_text())["endpoints"] == 1


def test_external_policy_validation_and_provenance(tmp_path, capsys):
    policy_path = tmp_path / "generated.policy.yaml"
    policy_path.write_text(
        'generated_by: "external test generator"\n'
        "status: unconfirmed\n"
        "resources:\n"
        "  Document:\n"
        "    confirmed: false\n"
        "    read: owner(owner_id)\n"
    )
    assert main(["validate-policy", str(policy_path)]) == 0
    validated = json.loads(capsys.readouterr().out)
    assert validated["valid"] is True
    assert validated["metadata"]["generated_by"] == "external test generator"

    policy = load_policy(policy_path)
    page = report.html_report([], policy)
    assert "generated_by=external test generator" in page
    assert "status=unconfirmed" in page


@pytest.mark.parametrize(("statement", "has_row"), [
    ("stmt = select(Document)", True),
    ("stmt = select(Document.title)", False),
    ("stmt = select(Document)\n    if flag:\n        stmt = select(Document.title)", False),
])
def test_direct_sqlmodel_helper_return_preserves_only_entity_updates(tmp_path, statement, has_row):
    (tmp_path / "models.py").write_text("class Document:\n    __tablename__ = 'documents'\n")
    (tmp_path / "app.py").write_text(f"""from fastapi import APIRouter, Depends
from sqlmodel import select
from models import Document

router = APIRouter()
def get_db(): pass

async def lookup(session, flag):
    {statement}
    return (await session.exec(stmt)).first()

@router.patch('/document')
async def edit(flag: bool, session=Depends(get_db)):
    item = await lookup(session, flag)
    if item:
        item.title = 'revised'
""")
    (tmp_path / "keyhole.policy.yaml").write_text("resources: {Document: {read: true, update: false}}")
    result, = scan(tmp_path)
    kinds = [e.effect.kind for e in result.effects if e.effect.resource == "Document"]
    assert kinds.count("read") == 1
    assert ("update" in kinds) == has_row


@pytest.mark.parametrize("import_path", ["sample.models.catalog", "..models.catalog"])
def test_namespace_helpers_keep_qualified_identity(tmp_path, import_path):
    package = tmp_path / "backend" / "sample"
    for folder in ["models", "routers", "other"]:
        (package / folder).mkdir(parents=True)
    (package / "__init__.py").touch()
    (package / "models" / "catalog.py").write_text("""
class Item:
    __tablename__ = 'items'

class Catalog:
    def lookup(self, session, key):
        return session.get(Item, key)

catalog = Catalog()
""")
    (package / "other" / "catalog.py").write_text("""
class Catalog:
    def lookup(self, session, key):
        return None

catalog = Catalog()
""")
    (package / "routers" / "catalog.py").write_text(f"""from fastapi import APIRouter, Depends
from {import_path} import catalog

router = APIRouter()
def get_db(): pass

@router.get('/items')
def items(key: int, session=Depends(get_db)):
    return catalog.lookup(session, key)
""")
    (tmp_path / "keyhole.policy.yaml").write_text("resources: {Item: {read: false}}")
    result, = scan(tmp_path)
    assert [(e.effect.kind, e.effect.resource) for e in result.effects] == [("read", "Item")]
