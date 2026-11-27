"""Module-level boolean helpers contribute real AIR guards on their truthy path."""
from textwrap import dedent, indent

from keyhole import air
from keyhole.adapters import FastAPISQLAlchemyAdapter
from keyhole.checker import check_endpoints
from keyhole.policy import load_policy


def extract(tmp_path, helpers, handler):
    (tmp_path / "checks.py").write_text(dedent(helpers))
    (tmp_path / "app.py").write_text(dedent("""\
        from fastapi import Depends, FastAPI, HTTPException
        from sqlmodel import Field, Session, SQLModel
        from checks import allowed
        app = FastAPI()

        class Folder(SQLModel, table=True):
            id: int = Field(primary_key=True)
            user_id: int
            name: str

        def get_current_user(): pass
        def get_db(): pass
        def get_service(): pass

        @app.patch("/folders/{folder_id}")
        async def edit(folder_id: int, user=Depends(get_current_user), db: Session=Depends(get_db),
                       service=Depends(get_service)):
        """) + indent(dedent(handler), "    "))
    path = tmp_path / "policy.yaml"
    path.write_text(dedent("""\
        principal: {id: user.id, dependencies: [get_current_user]}
        resources:
          Folder: {confirmed: true, read: true, update: owner(user_id)}
        """))
    policy = load_policy(path)
    endpoint, = FastAPISQLAlchemyAdapter().extract(tmp_path, {}, policy=policy)
    update, = [effect for effect in endpoint.effects if effect.kind == "update"]
    assert all(check.helper_site is not None for check in endpoint.unmodeled_checks)
    assert not endpoint.assumptions
    assert update.assumed_from is None
    return endpoint, policy, update.guards


def test_awaited_administrator(tmp_path):
    _, _, guards = extract(tmp_path, '''
        async def allowed(actor, *, resource, service):
            """Delegate administration checks for ordinary users."""
            if getattr(actor, "is_superuser", False):
                return True
            return await service.can_administer(resource=resource, user_id=actor.id)
    ''', """
        if not await allowed(user, service=service, resource="role"):
            raise HTTPException(403)
        folder = db.get(Folder, folder_id)
        folder.name = "edited"
    """)
    assert guards == [air.or_(
        air.eq(air.principal("is_superuser"), air.const(True)),
        air.member("can_administer", air.principal("id"), air.const("role")),
    )]


def test_owner_equality(tmp_path):
    endpoint, policy, guards = extract(tmp_path, """
        def allowed(row, actor):
            return row.user_id == actor.id
    """, """
        folder = db.get(Folder, folder_id)
        if not allowed(folder, user):
            raise HTTPException(403)
        return_value = "edited"
        folder.name = return_value
    """)
    assert guards == [air.eq(air.fld("user_id"), air.principal("id"))]
    result, = check_endpoints([endpoint], policy)
    assert result.verdict == "safe"
