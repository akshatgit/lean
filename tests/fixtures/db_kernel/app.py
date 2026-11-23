"""Move 2: generic SQLAlchemy/SQLModel idioms.  Every modeled idiom has a positive route
(the authorization is really there -> SAFE) and a negative twin (it is not -> VIOLATION)."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Field, SQLModel, col, func, select, update

router = APIRouter()


class Doc(SQLModel, table=True):
    id: int = Field(primary_key=True)
    owner_id: int
    title: str = ""


class DocCreate(BaseModel):
    title: str


class Peer(SQLModel, table=True):
    id: int = Field(primary_key=True)
    owner_id: int | None


class TicketBase(SQLModel):
    ticket_number: int = Field(primary_key=True)


class Ticket(TicketBase, table=True):
    id: int


class Pair(SQLModel, table=True):
    id: int = Field(primary_key=True)
    owner_id: int = Field(primary_key=True)


def get_current_user(): ...


def get_session(): ...


@router.get("/ticket/{number}")
async def ticket(number: int, session=Depends(get_session)):
    return await session.get(Ticket, number)


@router.get("/my-ticket")
async def my_ticket(session=Depends(get_session), user=Depends(get_current_user)):
    return await session.get(Ticket, user.id)


@router.get("/pair/{number}")
async def pair(number: int, session=Depends(get_session)):
    return await session.get(Pair, number)


@router.get("/shared-docs")
async def shared_docs(session=Depends(get_session), user=Depends(get_current_user)):
    return (await session.exec(select(Doc).where((Doc.owner_id == user.id) | col(Doc.owner_id).is_(None)))).all()


@router.get("/shared-peer-filter")
async def shared_peer_filter(session=Depends(get_session), user=Depends(get_current_user)):
    return (await session.exec(select(Doc).where(Peer.owner_id == None))).all()


@router.get("/null-owner-only")
async def null_owner_only(session=Depends(get_session)):
    return (await session.exec(select(Doc).where(Doc.owner_id == None))).all()


# ---------------------------------------------------------------- model-parametric helpers

async def fetch_owned(session, model, *, id_column, resource_id, owner_column, owner_id):
    stmt = select(model).where(id_column == resource_id).where(owner_column == owner_id)
    stmt = stmt.with_for_update().execution_options(populate_existing=True)
    return (await session.exec(stmt)).first()


async def fetch_any(session, model, *, id_column, resource_id):
    return (await session.exec(select(model).where(id_column == resource_id))).first()


async def fetch_by_mode(session, model, *, id_column, resource_id, owner_column, owner_id, wide: bool):
    if wide:                                   # a runtime switch: either statement may run
        stmt = select(model).where(id_column == resource_id)
    else:
        stmt = select(model).where(id_column == resource_id).where(owner_column == owner_id)
    return (await session.exec(stmt)).first()


@router.get("/generic/owned/{doc_id}")
async def generic_owned(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    return await fetch_owned(session, Doc, id_column=Doc.id, resource_id=doc_id,
                             owner_column=Doc.owner_id, owner_id=user.id)


@router.get("/generic/any/{doc_id}")
async def generic_any(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    return await fetch_any(session, Doc, id_column=Doc.id, resource_id=doc_id)


@router.get("/generic/mode/{doc_id}")
async def generic_mode(doc_id: int, wide: bool = False, session=Depends(get_session),
                       user=Depends(get_current_user)):
    return await fetch_by_mode(session, Doc, id_column=Doc.id, resource_id=doc_id,
                               owner_column=Doc.owner_id, owner_id=user.id, wide=wide)


# ---------------------------------------------------------------- statement-builder helpers

def owned_docs_stmt(owner_id: int):
    return select(Doc).where(Doc.owner_id == owner_id)


def all_docs_stmt():
    return select(Doc)


@router.get("/builder/owned/{doc_id}")
async def builder_owned(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    stmt = owned_docs_stmt(user.id).where(Doc.id == doc_id)
    return (await session.exec(stmt)).first()


@router.get("/builder/owned-inline")
async def builder_owned_inline(session=Depends(get_session), user=Depends(get_current_user)):
    return (await session.exec(owned_docs_stmt(user.id))).all()


@router.get("/builder/all/{doc_id}")
async def builder_all(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    stmt = all_docs_stmt().where(Doc.id == doc_id)
    return (await session.exec(stmt)).first()


# ---------------------------------------------------------------- filters added on one path

@router.get("/optional-checked/{doc_id}")
async def optional_checked(doc_id: int, skip: bool, session=Depends(get_session), user=Depends(get_current_user)):
    if skip:
        return None
    doc = await session.get(Doc, doc_id)
    if doc is None or doc.owner_id != user.id:
        raise HTTPException(status_code=404)
    return doc


@router.get("/optional-bypassed/{doc_id}")
async def optional_bypassed(doc_id: int, skip: bool, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    if skip:
        return doc
    if doc is None or doc.owner_id != user.id:
        raise HTTPException(status_code=404)
    return doc

@router.get("/nullable-owner/{doc_id}")
async def nullable_owner(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    if doc is None or (doc.owner_id is not None and doc.owner_id != user.id):
        raise HTTPException(status_code=404)
    return doc

@router.get("/conditional/partial-sql-and")
async def partial_sql_and(session=Depends(get_session), user=Depends(get_current_user)):
    return (await session.exec(select(Doc).where((Doc.id > 0) & (Doc.owner_id == user.id)))).all()


@router.get("/conditional/partial-sql-or")
async def partial_sql_or(session=Depends(get_session), user=Depends(get_current_user)):
    return (await session.exec(select(Doc).where((Doc.id > 0) | (Doc.owner_id == user.id)))).all()

@router.get("/conditional/python-and")
async def python_and(q: str, session=Depends(get_session), user=Depends(get_current_user)):
    stmt = select(Doc).where((Doc.title == q) and (Doc.owner_id == user.id))
    return (await session.exec(stmt)).all()


@router.get("/conditional/sql-and")
async def sql_and(q: str, session=Depends(get_session), user=Depends(get_current_user)):
    stmt = select(Doc).where((Doc.title == q) & (Doc.owner_id == user.id))
    return (await session.exec(stmt)).all()

@router.get("/conditional/narrowing")
async def conditional_narrowing(q: str = "", session=Depends(get_session), user=Depends(get_current_user)):
    stmt = select(Doc).where(Doc.owner_id == user.id)
    if q:
        stmt = stmt.where(Doc.title == q)       # optional extra filter: still owner-scoped
    return (await session.exec(stmt)).all()


@router.get("/conditional/owner-optional")
async def conditional_owner_optional(mine: bool = True, session=Depends(get_session),
                                     user=Depends(get_current_user)):
    stmt = select(Doc)
    if mine:
        stmt = stmt.where(Doc.owner_id == user.id)   # the owner filter is NOT on every path
    return (await session.exec(stmt)).all()


@router.get("/conditional/branch-built")
async def conditional_branch_built(mine: bool = True, session=Depends(get_session),
                                   user=Depends(get_current_user)):
    if mine:
        stmt = select(Doc).where(Doc.owner_id == user.id)
    else:
        stmt = select(Doc)
    return (await session.exec(stmt)).all()


# ---------------------------------------------------------------- aggregates / select_from

@router.get("/count/owned")
async def count_owned(session=Depends(get_session), user=Depends(get_current_user)):
    total = (await session.exec(select(func.count()).select_from(Doc).where(Doc.owner_id == user.id))).one()
    return {"total": total}


@router.get("/count/all")
async def count_all(session=Depends(get_session), user=Depends(get_current_user)):
    total = (await session.exec(select(func.count(Doc.id)))).one()
    return {"total": total}


# ---------------------------------------------------------------- session writes

@router.post("/write/create-owned")
async def write_create_owned(payload: DocCreate, session=Depends(get_session), user=Depends(get_current_user)):
    doc = Doc.model_validate(payload, update={"owner_id": user.id})
    session.add(doc)
    await session.commit()
    return {"ok": True}


@router.post("/write/create-owned-attr")
async def write_create_owned_attr(payload: DocCreate, session=Depends(get_session),
                                  user=Depends(get_current_user)):
    doc = Doc.model_validate(payload)
    doc.owner_id = user.id
    session.add(doc)
    return {"ok": True}


@router.post("/write/create-unowned")
async def write_create_unowned(payload: DocCreate, session=Depends(get_session), user=Depends(get_current_user)):
    doc = Doc.model_validate(payload)           # owner comes from nowhere
    session.add(doc)
    return {"ok": True}


@router.put("/write/merge/{doc_id}")
async def write_merge(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = Doc(id=doc_id, owner_id=user.id)      # upsert: overwrites whichever row has this id
    await session.merge(doc)
    return {"ok": True}


async def _purge(session, doc: Doc):
    await session.delete(doc)                    # a Doc we never saw being loaded or checked


@router.delete("/write/delete-untracked/{doc_id}")
async def write_delete_untracked(doc_id: int, payload: dict, session=Depends(get_session),
                                 user=Depends(get_current_user)):
    await _purge(session, payload["doc"])
    return {"ok": True}


@router.patch("/write/bulk-owned")
async def write_bulk_owned(title: str, session=Depends(get_session), user=Depends(get_current_user)):
    await session.exec(update(Doc).where(Doc.owner_id == user.id).values(title=title))
    return {"ok": True}


@router.patch("/write/bulk-all")
async def write_bulk_all(title: str, session=Depends(get_session), user=Depends(get_current_user)):
    await session.exec(update(Doc).values(title=title))
    return {"ok": True}


# ---------------------------------------------------------------- deep helper chains

async def _level5_checked(session, doc_id: int, user):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != user.id:
        raise HTTPException(status_code=404)
    return doc


async def _level4_checked(session, doc_id: int, user):
    return await _level5_checked(session, doc_id, user)


async def _level3_checked(session, doc_id: int, user):
    doc = await _level4_checked(session, doc_id, user)
    return doc


async def _level2_checked(session, doc_id: int, user):
    doc = await _level3_checked(session, doc_id, user)
    return doc


async def _level1_checked(session, doc_id: int, user):
    doc = await _level2_checked(session, doc_id, user)
    return doc


async def _level5_unchecked(session, doc_id: int, user):
    return await session.get(Doc, doc_id)


async def _level4_unchecked(session, doc_id: int, user):
    return await _level5_unchecked(session, doc_id, user)


async def _level3_unchecked(session, doc_id: int, user):
    return await _level4_unchecked(session, doc_id, user)


async def _level2_unchecked(session, doc_id: int, user):
    return await _level3_unchecked(session, doc_id, user)


async def _level1_unchecked(session, doc_id: int, user):
    return await _level2_unchecked(session, doc_id, user)


@router.get("/deep/checked/{doc_id}")
async def deep_checked(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    return await _level1_checked(session, doc_id, user)


@router.get("/deep/unchecked/{doc_id}")
async def deep_unchecked(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    return await _level1_unchecked(session, doc_id, user)


async def _recursive(session, doc_id: int, n: int):
    if n <= 0:
        return await session.get(Doc, doc_id)
    return await _recursive(session, doc_id, n - 1)


@router.get("/deep/recursive/{doc_id}")
async def deep_recursive(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    return await _recursive(session, doc_id, 3)


# ---------------------------------------------------------------- last assignment wins

@router.post("/write/create-owner-overwritten/{owner_id}")
async def write_create_owner_overwritten(owner_id: int, payload: DocCreate, session=Depends(get_session),
                                         user=Depends(get_current_user)):
    doc = Doc.model_validate(payload, update={"owner_id": user.id})
    doc.owner_id = owner_id                      # the caller's id is replaced by a request value
    session.add(doc)
    return {"ok": True}
