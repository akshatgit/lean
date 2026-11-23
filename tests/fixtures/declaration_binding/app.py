"""Policy declarations (adapter.ignore_calls) are bound and screened, never trusted by name.

`vendor` and `audit_sink` are not part of the repository (unreadable); `other` is.
  2a  a declared call handed a db handle / tracked row / callable, or called on the
      session, is NOT suppressed -> it is classified as undeclared (opaque -> UNKNOWN);
  2b  a bare declaration `foo` binds to an unreadable `vendor.foo`, never to the
      unrelated repository function `other.foo`;
  2c  a declaration for repository code that visibly reads the database is refuted:
      the read is modeled instead of suppressed."""
import audit_sink
import other
import vendor
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Field, SQLModel

router = APIRouter()


class Doc(SQLModel, table=True):
    id: int = Field(primary_key=True)
    owner_id: int


def get_current_user(): ...


def get_session(): ...


def new_session(): ...


async def _owned(doc_id: int, session, user):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != user.id:
        raise HTTPException(status_code=404)
    return doc


async def peek(doc_id: int):
    # In-repo, declared data-irrelevant in the policy -- but it visibly reads Doc.
    session = new_session()
    return await session.get(Doc, doc_id)


# ---------------- 2a: refused when handed a way to reach the database ----------------

@router.get("/passed-session/{doc_id}")
async def passed_session(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await _owned(doc_id, session, user)
    audit_sink.record(session, doc_id)              # handed the db session
    return doc


@router.get("/passed-row/{doc_id}")
async def passed_row(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await _owned(doc_id, session, user)
    audit_sink.record(doc)                          # handed a tracked row
    return doc


@router.get("/passed-callable/{doc_id}")
async def passed_callable(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await _owned(doc_id, session, user)
    audit_sink.record(doc_id, on_done=lambda: None)  # handed a callable
    return doc


@router.get("/session-receiver/{doc_id}")
async def session_receiver(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await _owned(doc_id, session, user)
    session.flush_metrics()                         # a method on the db handle
    return doc


@router.get("/passed-scalars/{doc_id}")
async def passed_scalars(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await _owned(doc_id, session, user)
    audit_sink.record(doc_id)                       # control: scalars only -> suppressed
    return doc


# ---------------- 2b: bound by identity, not by a bare last segment ----------------

@router.get("/name-collision/{doc_id}")
async def name_collision(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await _owned(doc_id, session, user)
    other.foo(doc_id)                               # unrelated repository `foo`: not declared
    return doc


@router.get("/leaf-unreadable/{doc_id}")
async def leaf_unreadable(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await _owned(doc_id, session, user)
    vendor.foo(doc_id)                              # control: unreadable `foo` -> suppressed
    return doc


def get_audit_ctx(session=Depends(get_session)):
    # Declared data-irrelevant, but FastAPI hands it the db session (2a for dependencies):
    # the declaration is refused and its (empty) body is analysed -- proved, not trusted.
    ...


@router.get("/declared-dependency-with-session/{doc_id}")
async def declared_dependency_with_session(doc_id: int, session=Depends(get_session),
                                           user=Depends(get_current_user),
                                           audit=Depends(get_audit_ctx)):
    return await _owned(doc_id, session, user)


# ---------------- 2c: a declaration the adapter can refute is rejected ----------------

@router.get("/refuted/{doc_id}")
async def refuted(doc_id: int):
    return await peek(doc_id)                       # declared irrelevant, but reads Doc
