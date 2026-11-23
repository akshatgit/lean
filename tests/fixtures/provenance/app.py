"""Assumption provenance: a verdict that rests on ANY unproven claim must not be clean green.

`vendor`, `audit_sink` and `permissions` are not part of the repository: the adapter cannot
read them.  The policy declares some of their calls data-irrelevant and one a guard."""
import audit_sink
import permissions
import vendor
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Field, SQLModel

router = APIRouter()


class Doc(SQLModel, table=True):
    id: int = Field(primary_key=True)
    owner_id: int


def get_current_user(): ...


def get_session(): ...


async def _owned(doc_id: int, session, user):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != user.id:
        raise HTTPException(status_code=404)
    return doc


# ---------------- control: nothing assumed -> clean SAFE / clean no_effects ----------------

@router.get("/clean/{doc_id}")
async def clean(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    return await _owned(doc_id, session, user)


@router.get("/clean-ping")
async def clean_ping(name: str = "x"):
    return {"name": name.strip()}


# ---------------- (a) green ONLY because an unreadable call was declared irrelevant --------

@router.get("/ignored-statement/{doc_id}")
async def ignored_statement(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await _owned(doc_id, session, user)
    audit_sink.record(doc_id)                       # statement position: `_helper`
    # (handed only a scalar: a session-passing variant must NOT be suppressed -- see
    #  tests/fixtures/declaration_binding)
    return doc


@router.get("/ignored-in-condition/{doc_id}")
async def ignored_in_condition(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await _owned(doc_id, session, user)
    if vendor.lookup(doc_id):                       # skipped position: totality sweep -> oracle
        return None
    return doc


@router.get("/ignored-no-effects/{key}")
async def ignored_no_effects(key: int):
    return {"value": [vendor.lookup(key)]}          # the endpoint's ONLY content


@router.get("/ignored-dependency/{doc_id}")
async def ignored_dependency(doc_id: int, client=Depends(vendor.get_vendor_client),
                             session=Depends(get_session), user=Depends(get_current_user)):
    return await _owned(doc_id, session, user)


# ---------------- (b) transitive: endpoint -> helper_a -> helper_b -> declared call --------

def helper_b(event: str) -> None:
    vendor.emit(event)                              # declared irrelevant, body unreadable


def helper_a(event: str) -> None:
    helper_b(event.upper())


@router.get("/transitive-first/{doc_id}")
async def transitive_first(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await _owned(doc_id, session, user)
    helper_a("read")                                # first use: the oracle computes the closure
    return doc


@router.get("/transitive-cached/{doc_id}")
async def transitive_cached(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await _owned(doc_id, session, user)
    helper_a("read-again")                          # second use: answered from the cache
    return doc


@router.get("/transitive-no-effects")
async def transitive_no_effects():
    return {"ok": [helper_a("ping")] is not None}   # cached, skipped position, no effects at all


def even(n: int) -> bool:
    return True if n <= 0 else odd(n - 1)


def odd(n: int) -> bool:
    helper_b("odd")                                 # a declaration inside a recursion cycle
    return False if n <= 0 else even(n - 1)


@router.get("/transitive-cycle/{doc_id}")
async def transitive_cycle(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await _owned(doc_id, session, user)
    return {"doc": doc, "parity": [odd(3), even(3)]}


# ---------------- (c) declared helper guard with no row argument ----------------------------

@router.get("/helper-guard/{doc_id}")
async def helper_guard(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    permissions.ensure_document_access(session, user, doc_id)   # declared: owner(owner_id)
    return await session.get(Doc, doc_id)


# ---------------- a violation past a suppressed call is a lead, not a finding ---------------

@router.get("/suppressed-then-idor/{doc_id}")
async def suppressed_then_idor(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    audit_sink.record(user, doc_id)                 # could, for all we know, deny the request
    return await session.get(Doc, doc_id)
