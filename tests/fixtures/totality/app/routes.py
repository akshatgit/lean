from fastapi import APIRouter, Depends, HTTPException

from . import lib
from .lib import (
    DbStore,
    Registry,
    Store,
    Touching,
    calls_unknown,
    even_helper,
    get_current_user,
    get_session,
    hidden_session_read,
    passthrough,
    ping_reads,
    shadowed_len_user,
)
from .models import Doc

router = APIRouter()


async def _owned(doc_id: int, session, current_user):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != current_user.id:
        raise HTTPException(status_code=404)
    return doc


# ===================== must be UNKNOWN: an extra call that is NOT provably effect-free =====================

def _guarded_then(extra):
    """All routes below load an owner-checked Doc (SAFE on its own) and then do `extra`."""


@router.get("/trap/untyped-receiver/{doc_id}")
async def trap_untyped_receiver(doc_id: int, payload: dict, session=Depends(get_session),
                                current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)
    thing = payload["thing"]
    return {"v": thing.get("x")}                       # dict *value*: type unknown


@router.get("/trap/rebound-name/{doc_id}")
async def trap_rebound_name(doc_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)
    box = {}
    box = lib.Registry()                                # no longer a plain dict
    return {"v": box.get(doc_id)}


@router.get("/trap/dict-subclass/{doc_id}")
async def trap_dict_subclass(doc_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)
    reg = Registry()
    return {"v": reg.get(doc_id)}


def _annotated_dict(mapping: dict, key: int):
    return mapping.get(key)                             # `dict` may be a Registry


@router.get("/trap/annotated-dict/{doc_id}")
async def trap_annotated_dict(doc_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)
    return {"v": _annotated_dict(Registry(), doc_id)}


@router.get("/trap/override/{doc_id}")
async def trap_override(doc_id: int, store: Store = Depends(DbStore), session=Depends(get_session),
                        current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)
    return {"v": store.load(doc_id)}                    # Store.load is pure, DbStore.load is not


@router.get("/trap/property/{doc_id}")
async def trap_property(doc_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)
    store = Store()
    return {"v": store.loader(Doc, doc_id)}             # calling a property's value


@router.get("/trap/closure-unknown/{doc_id}")
async def trap_closure_unknown(doc_id: int, payload: dict, session=Depends(get_session),
                               current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)
    return {"v": calls_unknown(payload)}                # helper has no db arg but an unknown callee


@router.get("/trap/hidden-session/{doc_id}")
async def trap_hidden_session(doc_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)
    other = doc_id + 1
    return {"v": [hidden_session_read(other)]}          # module-global session, list position


@router.get("/trap/mutual-recursion/{doc_id}")
async def trap_mutual_recursion(doc_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)
    return {"a": even_helper(2), "b": ping_reads(2)}    # even/odd pure; ping/pong read


@router.get("/trap/shadowed-builtin/{doc_id}")
async def trap_shadowed_builtin(doc_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)
    return {"n": [shadowed_len_user([1, 2])]}           # lib.len is not the builtin


@router.get("/trap/callback-kw/{doc_id}")
async def trap_callback_kw(doc_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)
    return {"v": sorted([doc_id + 1], key=hidden_session_read)}


@router.get("/trap/higher-order/{doc_id}")
async def trap_higher_order(doc_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)
    return {"v": list(map(hidden_session_read, [doc_id + 1]))}


@router.get("/trap/constructor/{doc_id}")
async def trap_constructor(doc_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)
    return {"v": [Touching(doc_id + 1)] is None}        # __init__ reads


@router.get("/trap/decorated-closure/{doc_id}")
async def trap_decorated_closure(doc_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)

    @passthrough
    def inner():
        return 1

    return {"v": [inner()]}                             # `inner` is whatever the decorator returned


@router.get("/trap/legacy-query-iter/{doc_id}")
async def trap_legacy_query_iter(doc_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)
    q = session.query(Doc)
    return {"n": len(list(q))}                          # list(q) executes the query


@router.patch("/trap/untracked-write/{doc_id}")
async def trap_untracked_write(doc_id: int, payload: dict, session=Depends(get_session),
                               current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)
    other = payload["row"]
    other.title = "changed"                             # write to an object we never tracked
    return {"ok": True}


# ===================== stale bindings: must NOT be SAFE =====================

async def _pair(session, doc_id: int):
    return await session.get(Doc, doc_id), 1


@router.delete("/stale/tuple-rebind/{doc_id}/{other_id}")
async def stale_tuple_rebind(doc_id: int, other_id: int, session=Depends(get_session),
                             current_user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != current_user.id:
        raise HTTPException(status_code=404)
    doc, _n = await _pair(session, other_id)            # `doc` is now an unchecked row
    await session.delete(doc)
    return {"ok": True}


@router.delete("/stale/unknown-rebind/{doc_id}/{other_id}")
async def stale_unknown_rebind(doc_id: int, other_id: int, payload: dict, session=Depends(get_session),
                               current_user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != current_user.id:
        raise HTTPException(status_code=404)
    doc = payload["rows"][other_id]
    await session.delete(doc)
    return {"ok": True}


@router.delete("/stale/loop-rebind/{doc_id}")
async def stale_loop_rebind(doc_id: int, payload: dict, session=Depends(get_session),
                            current_user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != current_user.id:
        raise HTTPException(status_code=404)
    for item in payload["rows"]:
        await session.delete(doc)                       # second iteration deletes `item`
        doc = item
    return {"ok": True}


# ===================== wrappers and injected classes =====================

@router.get("/trap/decorated-helper/{doc_id}")
async def trap_decorated_helper(doc_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    doc = await lib.load_checked(session, doc_id, current_user)   # the decorator defeats the check
    return doc


@router.get("/trap/class-dependency/{doc_id}")
async def trap_class_dependency(doc_id: int, loader: lib.Loader = Depends(), session=Depends(get_session),
                                current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)
    return {"ok": True}


def audit_everything(fn):
    return fn


@router.get("/trap/endpoint-decorator/{doc_id}")
@audit_everything
async def trap_endpoint_decorator(doc_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    await _owned(doc_id, session, current_user)
    return {"ok": True}
