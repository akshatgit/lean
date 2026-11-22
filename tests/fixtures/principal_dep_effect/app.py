"""A dependency taken for "the caller" because of its name must not hide what it does."""
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Field, SQLModel, select

import external_auth  # not part of the repository

router = APIRouter()


class User(SQLModel, table=True):
    id: int = Field(primary_key=True)
    token: str
    active: bool = True


class Doc(SQLModel, table=True):
    id: int = Field(primary_key=True)
    owner_id: int


def get_session(): ...


# ---- genuine principals -----------------------------------------------------------------

async def get_current_user(token: str, session=Depends(get_session)):
    user = (await session.exec(select(User).where(User.token == token))).first()
    if user is None:
        raise HTTPException(status_code=401)
    return user


async def get_current_active_user(user=Depends(get_current_user)):
    if not user.active:
        raise HTTPException(status_code=403)
    return user


@router.get("/ok/{doc_id}")
async def ok(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != user.id:
        raise HTTPException(status_code=404)
    return doc


@router.get("/ok-active/{doc_id}")
async def ok_active(doc_id: int, session=Depends(get_session), user=Depends(get_current_active_user)):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != user.id:
        raise HTTPException(status_code=404)
    return doc


# ---- a resource loader whose name merely contains "user" -------------------------------

async def get_doc_for_user(doc_id: int, session=Depends(get_session)):
    return await session.get(Doc, doc_id)                 # no ownership check at all


# `doc` is matched as the principal.  It is an arbitrary Doc; the dependency's read is an IDOR
# and `doc.id` is not the caller's id.
@router.get("/loader-as-principal/{doc_id}")
async def loader_as_principal(doc: Doc = Depends(get_doc_for_user), session=Depends(get_session)):
    return (await session.exec(select(Doc).where(Doc.owner_id == doc.id))).all()


async def get_doc_for_current_user(doc_id: int, user=Depends(get_current_user), session=Depends(get_session)):
    doc = await session.get(Doc, doc_id)                  # depends on the caller, checks nothing
    return doc


@router.get("/loader-with-principal/{doc_id}")
async def loader_with_principal(doc=Depends(get_doc_for_current_user)):
    return doc


async def get_owned_doc_for_current_user(doc_id: int, user=Depends(get_current_user),
                                         session=Depends(get_session)):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != user.id:
        raise HTTPException(status_code=404)
    return doc


# Control: the loader really checks ownership -> SAFE, and `doc` is a row, not the caller.
@router.get("/owned-loader/{doc_id}")
async def owned_loader(doc=Depends(get_owned_doc_for_current_user)):
    return doc


# ---- a real principal fetch with something extra hidden inside --------------------------

async def get_user_and_peek(token: str, peek_id: int, session=Depends(get_session)):
    await session.get(Doc, peek_id)                       # unrelated, unchecked read
    user = (await session.exec(select(User).where(User.token == token))).first()
    return user


@router.get("/hidden-read/{doc_id}")
async def hidden_read(doc_id: int, session=Depends(get_session), user=Depends(get_user_and_peek)):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != user.id:
        raise HTTPException(status_code=404)
    return doc


# ---- name-matched principal whose body cannot be read -----------------------------------

@router.get("/unreadable/{doc_id}")
async def unreadable(doc_id: int, session=Depends(get_session), user=Depends(external_auth.current_user)):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != user.id:
        raise HTTPException(status_code=404)
    return doc


# ---- route-level dependency that only looks like authentication -------------------------

async def require_user_can_see(doc_id: int, session=Depends(get_session)):
    await session.get(Doc, doc_id)                        # unchecked read, result discarded


@router.get("/route-dep/{doc_id}", dependencies=[Depends(require_user_can_see)])
async def route_dep(doc_id: int):
    return {"ok": True}


# ---- "the user" picked by an id from the URL is a lookup, not the caller ----------------

async def get_target_user(user_id: int, session=Depends(get_session)):
    target = await session.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404)
    return target


@router.get("/profile/{user_id}")
async def profile(target: User = Depends(get_target_user)):
    return target
