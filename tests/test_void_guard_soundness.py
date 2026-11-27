"""Adversarial soundness tests for VOID guard-by-raise helper synthesis (increment 2).

A void helper `if allow: return; ...; raise` guarantees `allow` on every normal return, so its
allow-condition may be attached as a guard to later effects — but ONLY when every non-allow path
raises. The negatives here pin the cases where a normal return can happen WITHOUT the allow
condition; attaching a guard there would be a false SAFE. Authored independently of the code.
"""
from textwrap import dedent, indent

from keyhole import air
from keyhole.adapters import FastAPISQLAlchemyAdapter
from keyhole.checker import check_endpoints
from keyhole.policy import load_policy


def scan(tmp_path, *, handler, helpers="", rule="owner(owner_id)", relations="", bypass=""):
    source = dedent("""\
        from fastapi import Depends, FastAPI, HTTPException
        from sqlmodel import Field, Session, SQLModel
        from vendor import external, audit
        app = FastAPI()

        class Folder(SQLModel, table=True):
            id: int = Field(primary_key=True)
            owner_id: int
            team_id: int
            name: str

        def get_current_user(): pass
        def get_db(): pass

        def can_admin(a, b):   # pure relation oracle
            return a == b
    """)
    source += "\n" + dedent(helpers) + "\n"
    source += dedent("""
        @app.patch("/folders/{folder_id}")
        def handler(folder_id: int, name: str, user=Depends(get_current_user), db: Session=Depends(get_db)):
    """)
    (tmp_path / "app.py").write_text(source + indent(dedent(handler), "    ") + "\n")

    policy_path = tmp_path / "policy.yaml"
    principal = "principal:\n  id: user.id\n  dependencies: [get_current_user]\n"
    if bypass:
        principal = f"principal:\n  id: user.id\n  dependencies: [get_current_user]\n  bypass: {bypass}\n"
    policy_path.write_text(
        principal + (relations or "")
        + dedent(f"""\
        resources:
          Folder:
            confirmed: true
            read: true
            update: {rule}
        """)
    )
    policy = load_policy(policy_path)
    endpoints = FastAPISQLAlchemyAdapter().extract(tmp_path, {}, policy=policy)
    result, = check_endpoints(endpoints, policy)
    update, = [e for e in result.effects if e.effect.kind == "update"]
    return result, update


LOAD = "folder = db.get(Folder, folder_id)"
WRITE = "folder.name = name"


def _no_clean_safe(result, update):
    assert update.verdict != "safe", update.effect.guards
    assert result.verdict != "safe"


# --------------------------------------------------------------------------- positives

def test_row_scoped_void_helper_flips_to_safe(tmp_path):
    """`def check(res, actor): if res.owner_id == actor: return; raise` — a bare statement guard
    attaches eq(owner_id, principal) to the row and proves SAFE with no provenance."""
    helpers = dedent("""\
        def check(res, actor):
            if res.owner_id == actor:
                return
            raise HTTPException(403)
    """)
    handler = f"{LOAD}\ncheck(folder, user.id)\n{WRITE}"
    result, update = scan(tmp_path, handler=handler, helpers=helpers, rule="owner(owner_id)")
    assert air.eq(air.fld("owner_id"), air.principal("id")) in update.effect.guards
    assert update.verdict == result.verdict == "safe"
    assert not result.provenance


def test_admin_gate_void_helper_synthesizes_global_guard(tmp_path):
    """The is_administrator-wrapper shape, called as a bare statement, yields the superuser-or-
    relation global guard (verdict depends on policy grant; shape is the contract here)."""
    helpers = dedent("""\
        def is_admin(u):
            if u.is_superuser:
                return True
            return can_admin(u.id, 'role')
        def require_admin(user):
            if is_admin(user):
                return
            audit()
            raise HTTPException(403)
    """)
    handler = f"{LOAD}\nrequire_admin(user)\n{WRITE}"
    result, update = scan(tmp_path, handler=handler, helpers=helpers)
    want = air.or_(air.eq(air.principal("is_superuser"), air.const(True)),
                   air.member("can_admin", air.principal("id"), air.const("role")))
    assert want in update.effect.guards, update.effect.guards


# --------------------------------------------------------------- negative controls (soundness)

def test_tail_can_return_normally_declines(tmp_path):
    """THE critical test. A second `return` in the tail means the function can return normally
    WITHOUT the allow condition. Must attach no guard."""
    helpers = dedent("""\
        def check(res, actor):
            if res.owner_id == actor:
                return
            if external():
                return
            raise HTTPException(403)
    """)
    handler = f"{LOAD}\ncheck(folder, user.id)\n{WRITE}"
    result, update = scan(tmp_path, handler=handler, helpers=helpers, rule="owner(owner_id)")
    assert air.eq(air.fld("owner_id"), air.principal("id")) not in update.effect.guards
    _no_clean_safe(result, update)


def test_no_final_raise_declines(tmp_path):
    """No unconditional raise: the helper returns None normally even when NOT allowed. Decline."""
    helpers = dedent("""\
        def check(res, actor):
            if res.owner_id == actor:
                return
            audit()
    """)
    handler = f"{LOAD}\ncheck(folder, user.id)\n{WRITE}"
    result, update = scan(tmp_path, handler=handler, helpers=helpers, rule="owner(owner_id)")
    assert air.eq(air.fld("owner_id"), air.principal("id")) not in update.effect.guards
    _no_clean_safe(result, update)


def test_conditional_tail_raise_declines(tmp_path):
    """Tail raise is itself conditional (`if x: raise`), so a non-allow path can fall through and
    return None. Decline."""
    helpers = dedent("""\
        def check(res, actor):
            if res.owner_id == actor:
                return
            if external():
                raise HTTPException(403)
    """)
    handler = f"{LOAD}\ncheck(folder, user.id)\n{WRITE}"
    result, update = scan(tmp_path, handler=handler, helpers=helpers, rule="owner(owner_id)")
    assert air.eq(air.fld("owner_id"), air.principal("id")) not in update.effect.guards
    _no_clean_safe(result, update)


def test_opaque_allow_condition_declines(tmp_path):
    """`if external(): return; raise` — the allow condition is opaque, so the guard is vacuous
    (True) and must not be emitted."""
    helpers = dedent("""\
        def check(res, actor):
            if external():
                return
            raise HTTPException(403)
    """)
    handler = f"{LOAD}\ncheck(folder, user.id)\n{WRITE}"
    result, update = scan(tmp_path, handler=handler, helpers=helpers, rule="owner(owner_id)")
    assert update.effect.guards == []
    _no_clean_safe(result, update)


def test_starargs_void_helper_declines(tmp_path):
    helpers = dedent("""\
        def check(*args):
            if args[0].owner_id == args[1]:
                return
            raise HTTPException(403)
    """)
    handler = f"{LOAD}\ncheck(folder, user.id)\n{WRITE}"
    result, update = scan(tmp_path, handler=handler, helpers=helpers, rule="owner(owner_id)")
    assert update.effect.guards == []
    _no_clean_safe(result, update)


def test_decorated_void_helper_declines(tmp_path):
    helpers = dedent("""\
        def deco(f):
            return f
        @deco
        def check(res, actor):
            if res.owner_id == actor:
                return
            raise HTTPException(403)
    """)
    handler = f"{LOAD}\ncheck(folder, user.id)\n{WRITE}"
    result, update = scan(tmp_path, handler=handler, helpers=helpers, rule="owner(owner_id)")
    assert update.effect.guards == []
    _no_clean_safe(result, update)
