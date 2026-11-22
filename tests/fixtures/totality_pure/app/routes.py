"""Every call besides the owner-checked load is PROVABLY unable to touch the database,
by import identity, receiver type, or transitive closure.  These routes must be SAFE."""
from fastapi import APIRouter, Depends, HTTPException

from .lib import Formatter, describe, even_helper, get_current_user, get_session, logger, slugify
from .models import Doc, DocOut

router = APIRouter()


@router.get("/pure/{doc_id}")
async def pure(doc_id: int, verbose: bool = False, session=Depends(get_session),
               current_user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    if not doc or doc.owner_id != current_user.id:
        raise HTTPException(status_code=404)
    meta = {"kind": "doc"}
    label = slugify("My Title") if verbose else describe(meta)
    tags = "a,b".split(",")
    logger.info("served %s", label)
    out = DocOut(id=doc_id, title=Formatter().render(label)).model_dump()
    if even_helper(4) and len(tags) > 1 and meta.get("kind"):
        out["tags"] = sorted(tags)
    return out


@router.get("/pure-no-effects")
async def pure_no_effects(name: str = "x"):
    payload = {"name": name.strip().lower(), "ok": even_helper(2)}
    logger.info("ping %s", payload)
    return payload
