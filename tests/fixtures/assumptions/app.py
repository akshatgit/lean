"""Assumptions file fixtures.  `vendor` is not part of the repository."""
import vendor
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Field, SQLModel

router = APIRouter()


class Doc(SQLModel, table=True):
    id: int = Field(primary_key=True)
    owner_id: int


def get_current_user(): ...


def get_session(): ...


# ---------------------------------------------------------------- service locator (returns_type)

class DocService:
    async def load_any(self, session, doc_id: int):
        return await session.get(Doc, doc_id)                 # no ownership check

    async def load_owned(self, session, doc_id: int, user):
        doc = await session.get(Doc, doc_id)
        if not doc or doc.owner_id != user.id:
            raise HTTPException(status_code=404)
        return doc


_REGISTRY = {}


def get_service(name: str):
    """Dynamic lookup: nothing in the code says what comes back."""
    factory = _REGISTRY[name]
    return factory()


def get_doc_service():
    return get_service("docs")


@router.get("/locator/any/{doc_id}")
async def locator_any(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    service = get_doc_service()
    return await service.load_any(session, doc_id)


@router.get("/locator/owned/{doc_id}")
async def locator_owned(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    service = get_doc_service()
    return await service.load_owned(session, doc_id, user)


# ---------------------------------------------------------------- effects: [] (irrelevance)

@router.get("/emit/scalars/{doc_id}")
async def emit_scalars(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != user.id:
        raise HTTPException(status_code=404)
    vendor.emit("read", doc_id)                               # only scalars
    return doc


@router.get("/emit/session/{doc_id}")
async def emit_session(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != user.id:
        raise HTTPException(status_code=404)
    vendor.emit("read", session)                              # handed the session
    return doc


# ---------------------------------------------------------------- effects: [...] (positive model)

@router.get("/audit/{doc_id}")
async def audited(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    vendor.load_document(session, doc_id)                     # declared: reads Doc by id
    return {"ok": True}


# ---------------------------------------------------------------- ensures (guard facts)

def _same(a: int, b: int) -> bool:
    return a == b


def ensure_owner(owner_id: int, user) -> None:
    """Raises unless the caller owns it -- through a comparison the adapter cannot turn
    into a guard (a call-valued condition)."""
    if not _same(owner_id, user.id):
        raise HTTPException(status_code=403)


@router.get("/ensures/principal/{doc_id}")
async def ensures_principal(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    ensure_owner(doc.owner_id, user)
    return doc


@router.get("/ensures/other-user/{doc_id}/{other_id}")
async def ensures_other_user(doc_id: int, other_id: int, session=Depends(get_session),
                             user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    other = vendor.lookup_user(other_id)
    ensure_owner(doc.owner_id, other)                         # checked against somebody else
    return doc


# ---------------------------------------------------------------- principal: true

def get_actor():                                              # nothing in the name says "user"
    return vendor.actor_from_request()


@router.get("/actor/{doc_id}")
async def actor_route(doc_id: int, session=Depends(get_session), actor=Depends(get_actor)):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != actor.id:
        raise HTTPException(status_code=404)
    return doc


# ---------------------------------------------------------------- transitive use (oracle cache)

def notify(kind: str) -> None:
    vendor.emit(kind, 1)


@router.get("/emit/transitive/{doc_id}")
async def emit_transitive(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != user.id:
        raise HTTPException(status_code=404)
    return {"doc": doc, "sent": [notify("read") for _ in range(1)]}
