"""Boolean checks authorize a particular use on the success path."""
from textwrap import dedent, indent

import pytest

from keyhole import air
from keyhole.adapters import FastAPISQLAlchemyAdapter
from keyhole.checker import check_endpoints
from keyhole.policy import load_policy


LOAD = "folder = db.get(Folder, folder_id)"
WRITE = "folder.name = name"
OWNER = "return resource.owner_id == actor"
CHECK = "if not access(user.id, folder): raise HTTPException(403)"


def scan(tmp_path, handler, helper=None, declaration=None, rule="owner(owner_id)", *, async_helper=False):
    source = dedent("""\
        from fastapi import Depends, FastAPI, HTTPException
        from sqlmodel import Field, Session, SQLModel
        from vendor import access, audit
        app = FastAPI()

        class Folder(SQLModel, table=True):
            id: int = Field(primary_key=True)
            owner_id: int
            other_id: int
            name: str

        def get_current_user(): pass
        def get_db(): pass
    """)
    if helper is not None:
        source = source.replace("from vendor import access, audit", "from vendor import audit")
        prefix = "async " if async_helper else ""
        source += f"\n{prefix}def access(actor, resource):\n" + indent(helper, "    ") + "\n"
    source += dedent("""
        @app.patch("/folders/{folder_id}")
        def handler(folder_id: int, other_id: int, name: str, user=Depends(get_current_user), db: Session=Depends(get_db)):
    """)
    (tmp_path / "app.py").write_text(source + indent(handler, "    ") + "\n")
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(dedent(f"""\
        principal: {{id: user.id, dependencies: [get_current_user]}}
        resources:
          Folder:
            confirmed: true
            read: true
            update: {rule}
    """) + (f"helpers:\n  access: {declaration}\n" if declaration else ""))
    policy = load_policy(policy_path)
    endpoints = FastAPISQLAlchemyAdapter().extract(tmp_path, {}, policy=policy)
    result, = check_endpoints(endpoints, policy)
    update, = [e for e in result.effects if e.effect.kind == "update"]
    return result, update


@pytest.mark.parametrize("condition", [
    CHECK + "\n" + WRITE,
    "if access(resource=folder, actor=user.id):\n    " + WRITE,
])
def test_verified_return(tmp_path, condition):
    result, update = scan(tmp_path, LOAD + "\n" + condition, OWNER, "owner(other_id)")
    assert update.verdict == result.verdict == "safe"
    assert update.effect.guards == [air.eq(air.fld("owner_id"), air.principal("id"))]
    assert all(not e.effect.guards for e in result.effects if e.effect.kind == "read")
    assert not result.provenance


@pytest.mark.parametrize(("body", "condition"), [
    ("return resource.other_id == actor", CHECK),
    ("return True", CHECK),
    ("return resource.owner_id == actor or True", CHECK),
    (OWNER, CHECK.replace("user.id", "other_id")),
    (OWNER, CHECK.replace("user.id, folder", "*(user.id, folder)")),
    (OWNER, CHECK.replace("user.id, folder", "**{'actor': user.id, 'resource': folder}")),
    (OWNER, "if access(user.id, folder): return"),
    (OWNER, "if not access(user.id, folder): pass"),
    (OWNER, "if not (access(user.id, folder) or name): return"),
])
def test_unproved_return_cannot_borrow_declaration(tmp_path, body, condition):
    result, update = scan(tmp_path, "\n".join([LOAD, condition, WRITE]), body, "owner(owner_id)")
    assert result.verdict == update.verdict == "possible_violation"
    assert not result.provenance


def test_no_guard(tmp_path):
    # As in the runner regression, an opaque call can block the unguarded access.
    result, update = scan(tmp_path, "\n".join(["audit()", LOAD, WRITE]))
    assert result.verdict == update.verdict == "possible_violation"
    assert update.effect.guards == []


@pytest.mark.parametrize("gate", [
    "if not access(user.id, folder_id, db): raise HTTPException(403)\n",
    "if not access(user.id, folder_id, db): return\n",
    "if not access(user.id, folder_id, db): folder_id = None\nif folder_id is None: return\n",
])
def test_declared_member_by_id(tmp_path, gate):
    rule = "member(folder_write, id)"
    load = "folder = db.query(Folder).filter(Folder.id == folder_id).first()"
    result, update = scan(tmp_path, gate + load + "\n" + WRITE, declaration=rule, rule=rule)
    assert result.verdict == update.verdict == "safe_assumed"
    assert update.effect.assumed_from == "helper-guard:access"
    assert "helper-guard:access" in result.provenance
    assert update.effect.selector == air.eq(air.fld("id"), air.param("folder_id"))
    assert update.effect.guards == [air.member("folder_write", air.principal("id"), air.param("folder_id"))]


def test_declared_row(tmp_path):
    result, update = scan(tmp_path, "\n".join([LOAD, CHECK, WRITE]), declaration="owner(owner_id)")
    assert result.verdict == update.verdict == "safe_assumed"
    read, = [e for e in result.effects if e.effect.kind == "read"]
    assert read.verdict == "safe" and not read.effect.guards


@pytest.mark.parametrize(("gate", "key"), [
    ("if not access(user.id, folder_id): return", "other_id"),
    ("if access(user.id, folder_id): return", "folder_id"),
    ("if not access(user.id, folder_id): pass", "folder_id"),
    ("if not access(user.id, folder_id): other_id = None", "folder_id"),
    ("if not access(user.id, folder_id): folder_id = other_id", "folder_id"),
    ("if not access(user.id, *args, folder_id): return", "folder_id"),
    ("if not access(user.id, folder_id, **kwargs): return", "folder_id"),
    ("if not access(user.id, folder_id, other_id): return", "folder_id"),
    ("if not access(other_id, folder_id): return", "folder_id"),
    ("ok = access(user.id, folder_id)\nif not ok: pass", "folder_id"),
    ("if not (access(user.id, folder_id) or name): return", "folder_id"),
])
def test_declared_fact_cannot_escape_checked_id_or_branch(tmp_path, gate, key):
    rule = "member(folder_write, id)"
    result, update = scan(tmp_path, "\n".join([gate, LOAD.replace(", folder_id", ", " + key), WRITE]),
                          declaration=rule, rule=rule)
    assert result.verdict == update.verdict == "possible_violation"
    assert not update.effect.guards


def test_positive_branch_does_not_guard_later_write(tmp_path):
    result, update = scan(tmp_path, "\n".join([
        LOAD, "if access(user.id, folder):", "    pass", WRITE,
    ]), OWNER)
    assert result.verdict == update.verdict == "possible_violation"
    assert not update.effect.guards


def test_check_accepts_principal_object(tmp_path):
    result, update = scan(tmp_path, "\n".join([LOAD, CHECK.replace("user.id", "user"), WRITE]),
                          "return actor.id == resource.owner_id")
    assert result.verdict == update.verdict == "safe"


@pytest.mark.parametrize("body", [OWNER, "if resource.owner_id != actor: raise HTTPException(403)\nreturn True"])
def test_readable_async_check_must_actually_run(tmp_path, body):
    result, update = scan(tmp_path, "\n".join([LOAD, CHECK, WRITE]), body, "owner(owner_id)", async_helper=True)
    assert result.verdict == update.verdict == "possible_violation"
    assert not any(e.effect.guards for e in result.effects)


def test_positive_membership_check(tmp_path):
    rule = "member(id)"
    result, update = scan(tmp_path, "if access(user, folder_id):\n" + indent(LOAD + "\n" + WRITE, "    "),
                          declaration=rule, rule=rule)
    assert result.verdict == update.verdict == "safe_assumed"


def test_row_check_does_not_guard_another_loaded_row(tmp_path):
    handler = "\n".join([LOAD.replace("folder =", "other =").replace(", folder_id", ", other_id"),
                         LOAD, CHECK, "other.name = name"])
    result, update = scan(tmp_path, handler, OWNER, "owner(owner_id)")
    assert result.verdict == update.verdict == "possible_violation"
    assert update.effect.selector == air.eq(air.fld("id"), air.param("other_id"))
    assert not update.effect.guards


def test_previously_rebound_id_is_not_the_input(tmp_path):
    rule = "member(folder_write, id)"
    handler = "\n".join(["folder_id = other_id", "if not access(user.id, folder_id): return", LOAD, WRITE])
    result, update = scan(tmp_path, handler, declaration=rule, rule=rule)
    assert result.verdict == update.verdict == "possible_violation"
    assert not update.effect.guards
