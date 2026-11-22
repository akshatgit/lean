"""Minimal mirrors of five Langflow endpoints where a DB-relevant call sits in a position
the statement walker does not model.  Every route here must be UNKNOWN: the owner-checked
flow read is modeled and SAFE, but the extra call is not, so the proof is incomplete."""
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import select

from .deps import get_current_user, get_flow, get_session
from .models import Flow, Record, User

router = APIRouter()


async def _legacy_flow_storage_allowed(session, flow_id: int) -> bool:
    return await session.get(User, flow_id) is None


# --- mirror of GET /files/download/{flow_id}/{file_name}: helper call inside a BoolOp
@router.get("/files/download/{flow_id}/{file_name}")
async def download_file(file_name: str, flow: Flow = Depends(get_flow), session=Depends(get_session)):
    extension = file_name.split(".")[-1]
    if not extension:
        raise HTTPException(status_code=500)
    allow_legacy = session is not None and await _legacy_flow_storage_allowed(session, flow.id)
    return {"legacy": bool(allow_legacy), "name": file_name}


# --- mirror of GET /files/list/{flow_id}: the same BoolOp, inside try/except
@router.get("/files/list/{flow_id}")
async def list_files(flow: Flow = Depends(get_flow), session=Depends(get_session)):
    try:
        allow_legacy = session is not None and await _legacy_flow_storage_allowed(session, flow.id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
    return {"files": [], "legacy": bool(allow_legacy)}


async def _state(session, record_id: int) -> dict:
    row = await session.get(Record, record_id)
    return {"payload": row.payload}


# --- mirror of PUT /migration/destinations: helper call splatted into a returned dict
@router.put("/migration/destinations/{record_id}")
async def set_destinations(record_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    results = ["ok"]
    return {**await _state(session, record_id), "results": results}


async def get_enabled_providers_for_user(session, user_id: int):
    rows = (await session.exec(select(Flow).where(Flow.user_id == user_id))).all()
    return [r.name for r in rows], len(rows)


# --- mirror of GET /agentic/check-config: tuple-unpacking of a DB helper's result
@router.get("/agentic/check-config")
async def check_config(session=Depends(get_session), current_user=Depends(get_current_user)):
    enabled_providers, _ = await get_enabled_providers_for_user(session, current_user.id)
    return {"configured": bool(enabled_providers)}


@asynccontextmanager
async def session_scope_readonly():
    yield get_session()


async def _cached_flow_component_usage():
    async with session_scope_readonly() as session:
        flows = (await session.exec(select(Flow))).all()
    return flows, len(flows)


# --- mirror of GET /catalog-policy/usage/flows: tuple-unpacking, helper opens its own session
@router.get("/catalog-policy/usage/flows")
async def get_component_usage_flows(current_user=Depends(get_current_user)):
    usage, _flows_scanned = await _cached_flow_component_usage()
    return {"flows": [f.name for f in usage]}


# --- the other positions catalogued in the gap analysis --------------------------------

@router.get("/skip/if-test/{flow_id}")
async def skip_if_test(flow_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    if await session.get(Flow, flow_id) is None:
        raise HTTPException(status_code=404)
    return {"exists": True}


@router.get("/skip/ifexp/{flow_id}")
async def skip_ifexp(flow_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    flow = await session.get(Flow, flow_id) if flow_id else None
    return {"found": flow is not None}


@router.get("/skip/subscript/{flow_id}")
async def skip_subscript(flow_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    first = (await session.exec(select(Flow).where(Flow.id == flow_id))).all()[0]
    return {"name": first.name}


@router.get("/skip/comprehension")
async def skip_comprehension(session=Depends(get_session), current_user=Depends(get_current_user)):
    return [f.name for f in await session.exec(select(Flow))]


@router.get("/skip/for-iter")
async def skip_for_iter(session=Depends(get_session), current_user=Depends(get_current_user)):
    names = []
    for f in await session.exec(select(Flow)):
        names.append(f.name)
    return {"names": names}


@router.get("/skip/with-item")
async def skip_with_item(current_user=Depends(get_current_user)):
    async with session_scope_readonly() as s:
        names = [f.name for f in (await s.exec(select(Flow))).all()]
    return {"names": names}


@router.delete("/skip/closure/{flow_id}")
async def skip_closure(flow_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    async def _attempt():
        flow = await session.get(Flow, flow_id)
        await session.delete(flow)

    await _attempt()
    return {"ok": True}


@router.get("/skip/lambda/{flow_id}")
async def skip_lambda(flow_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    load = lambda: session.get(Flow, flow_id)  # noqa: E731
    return {"flow": await load()}


@router.get("/skip/kwarg/{flow_id}")
async def skip_kwarg(flow_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    return dict(found=[await session.get(Flow, flow_id)] != [None])


@router.get("/skip/fstring/{flow_id}")
async def skip_fstring(flow_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    label = f"flow={(await session.get(Flow, flow_id)).name}"
    return {"label": label}


@router.get("/skip/raise/{flow_id}")
async def skip_raise(flow_id: int, session=Depends(get_session), current_user=Depends(get_current_user)):
    raise HTTPException(status_code=400, detail=str(await session.get(Flow, flow_id)))


async def _load_unchecked(flow_id: int, session=Depends(get_session)):
    return await session.get(Flow, flow_id)


@router.get("/skip/unresolved-dependency/{flow_id}")
async def skip_unresolved_dependency(flow_id: int, thing=Depends(some_missing_dependency)):  # noqa: F821
    return {"ok": True}
