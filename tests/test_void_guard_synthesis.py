"""Effects following a guard-by-raise helper inherit its normal-return condition."""
from keyhole import air
from keyhole.checker import check_endpoints

from test_guard_synthesis import extract


def test_delegated_administrator_before_row_load(tmp_path):
    endpoint, _, guards = extract(tmp_path, '''
        async def is_admin(actor, *, resource, service):
            if getattr(actor, "is_superuser", False):
                return True
            return await service.can_administer(user_id=actor.id, resource=resource)

        async def allowed(user, *, authorization):
            """Check before the handler loads a row."""
            if await is_admin(user, resource="role", service=authorization):
                return
            await authorization.audit_deny()
            raise PermissionError()
    ''', """
        await allowed(user, authorization=service)
        folder = db.get(Folder, folder_id)
        folder.name = "edited"
    """)
    expected = [air.or_(
        air.eq(air.principal("is_superuser"), air.const(True)),
        air.member("can_administer", air.principal("id"), air.const("role")),
    )]
    read, = [effect for effect in endpoint.effects if effect.kind == "read"]
    assert read.guards == guards == expected


def test_void_owner_guard_on_loaded_row(tmp_path):
    endpoint, policy, guards = extract(tmp_path, """
        def allowed(row, actor):
            if row.user_id == actor:
                return
            raise PermissionError()
    """, """
        folder = db.get(Folder, folder_id)
        allowed(folder, user.id)
        folder.name = "edited"
    """)
    expected = air.eq(air.fld("user_id"), air.principal("id"))
    assert guards and all(guard == expected for guard in guards)
    result, = check_endpoints([endpoint], policy)
    assert result.verdict == "safe"
