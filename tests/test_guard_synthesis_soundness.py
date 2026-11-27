"""Adversarial soundness tests for guard synthesis from boolean authorization helpers.

A synthesized guard joins the Lean hypothesis (`guards ∧ selector ⊨ policy`). A guard STRONGER
than the code's real guarantee is a false SAFE — the one catastrophic failure. Every test here
pins either (a) the exact predicate synthesized, or (b) that NO clean `safe` is produced when the
code does not justify it. Authored independently of the implementation; it is the contract.
"""
from textwrap import dedent, indent

from keyhole import air
from keyhole.adapters import FastAPISQLAlchemyAdapter
from keyhole.checker import check_endpoints
from keyhole.policy import load_policy


def scan(tmp_path, *, handler, helpers="", rule="owner(owner_id)", relations="", bypass="",
         confirmed=True):
    """Build a one-endpoint app and return (endpoint_result, the update EffectResult).

    `helpers` is free module-level source (functions, imports). The handler body is indented
    into `handler`. `rule` is the Folder.update policy rule; `relations`/`bypass` are optional.
    """
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

        def has_role(a, b):   # pure relation oracle: no DB effect, modeled symbolically as member()
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
        principal
        + (relations or "")
        + dedent(f"""\
        resources:
          Folder:
            confirmed: {str(confirmed).lower()}
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
HAS_ROLE_REL = "relations:\n  has_role: {table: t, subject: s, object: o}\n"


# --------------------------------------------------------------------------- positive (the point)

def test_delegating_helper_compiles_to_member_over_row_field(tmp_path):
    """`return has_role(actor, resource.team_id)` -> member(has_role, principal.id, row.team_id),
    and with a matching policy the write proves SAFE with no provenance (a proof, not an assumption)."""
    helpers = "def access(actor, resource):\n    return has_role(actor, resource.team_id)\n"
    handler = f"{LOAD}\nif not access(user.id, folder):\n    raise HTTPException(403)\n{WRITE}"
    result, update = scan(tmp_path, handler=handler, helpers=helpers,
                          rule="member(has_role, team_id)", relations=HAS_ROLE_REL)
    assert air.member("has_role", air.principal("id"), air.fld("team_id")) in update.effect.guards
    assert update.verdict == result.verdict == "safe"
    assert not result.provenance


def test_async_superuser_or_relation_shape(tmp_path):
    """The is_administrator family. Must synthesize the FULL disjunction; neither disjunct alone
    (each would be unsound in a different direction)."""
    helpers = dedent("""\
        async def is_admin(user, folder):
            if user.is_superuser:
                return True
            return has_role(user.id, folder.team_id)
    """)
    handler = f"{LOAD}\nif not await is_admin(user, folder):\n    raise HTTPException(403)\n{WRITE}"
    result, update = scan(tmp_path, handler=handler, helpers=helpers,
                          rule="member(has_role, team_id)", relations=HAS_ROLE_REL)
    g = update.effect.guards
    want = air.or_(air.eq(air.principal("is_superuser"), air.const(True)),
                   air.member("has_role", air.principal("id"), air.fld("team_id")))
    assert want in g, g


# --------------------------------------------------------------- negative controls (soundness)

def _no_clean_safe(result, update):
    assert update.verdict != "safe", update.effect.guards
    assert result.verdict != "safe"


def test_unconditional_true_emits_no_guard(tmp_path):
    helpers = "def access(actor, resource):\n    return True\n"
    handler = f"{LOAD}\nif not access(user.id, folder):\n    raise HTTPException(403)\n{WRITE}"
    result, update = scan(tmp_path, handler=handler, helpers=helpers)
    assert update.effect.guards == []
    _no_clean_safe(result, update)


def test_opaque_disjunct_must_widen_and_decline(tmp_path):
    """THE critical test. The function can return True via the opaque branch, so the owner
    equality alone is STRONGER than reality. Must widen to True and decline — no eq guard."""
    helpers = dedent("""\
        def access(actor, resource):
            if external():
                return True
            return resource.owner_id == actor
    """)
    handler = f"{LOAD}\nif not access(user.id, folder):\n    raise HTTPException(403)\n{WRITE}"
    result, update = scan(tmp_path, handler=handler, helpers=helpers, rule="owner(owner_id)")
    assert air.eq(air.fld("owner_id"), air.principal("id")) not in update.effect.guards
    _no_clean_safe(result, update)


def test_plain_bool_param_is_not_a_guard(tmp_path):
    helpers = "def access(actor, resource, flag):\n    return flag\n"
    handler = f"{LOAD}\nif not access(user.id, folder, True):\n    raise HTTPException(403)\n{WRITE}"
    result, update = scan(tmp_path, handler=handler, helpers=helpers)
    assert update.effect.guards == []
    _no_clean_safe(result, update)


def test_relation_subject_must_be_the_principal(tmp_path):
    """Subject is a ROW FIELD, not the caller. A principal-subject policy must not be satisfied."""
    helpers = "def access(actor, resource):\n    return has_role(resource.owner_id, resource.team_id)\n"
    handler = f"{LOAD}\nif not access(user.id, folder):\n    raise HTTPException(403)\n{WRITE}"
    result, update = scan(tmp_path, handler=handler, helpers=helpers,
                          rule="member(has_role, team_id)", relations=HAS_ROLE_REL)
    assert air.member("has_role", air.principal("id"), air.fld("team_id")) not in update.effect.guards
    _no_clean_safe(result, update)


def test_starargs_helper_declines(tmp_path):
    helpers = "def access(*args):\n    return args[0].owner_id == args[1]\n"
    handler = f"{LOAD}\nif not access(folder, user.id):\n    raise HTTPException(403)\n{WRITE}"
    result, update = scan(tmp_path, handler=handler, helpers=helpers, rule="owner(owner_id)")
    assert update.effect.guards == []
    _no_clean_safe(result, update)


def test_decorated_helper_declines(tmp_path):
    helpers = dedent("""\
        def deco(f):
            return f
        @deco
        def access(actor, resource):
            return has_role(actor, resource.team_id)
    """)
    handler = f"{LOAD}\nif not access(user.id, folder):\n    raise HTTPException(403)\n{WRITE}"
    result, update = scan(tmp_path, handler=handler, helpers=helpers,
                          rule="member(has_role, team_id)", relations=HAS_ROLE_REL)
    assert update.effect.guards == []
    _no_clean_safe(result, update)


def test_wrong_field_does_not_borrow_rule(tmp_path):
    """Helper checks owner_id, but the policy keys on team_id; must not satisfy it."""
    helpers = "def access(actor, resource):\n    return resource.owner_id == actor\n"
    handler = f"{LOAD}\nif not access(user.id, folder):\n    raise HTTPException(403)\n{WRITE}"
    result, update = scan(tmp_path, handler=handler, helpers=helpers, rule="owner(team_id)")
    _no_clean_safe(result, update)
