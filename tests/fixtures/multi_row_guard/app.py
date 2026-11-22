"""A guard may only constrain the row whose fields it actually tests.

Every route loads a Doc and a Folder by attacker-chosen ids.  Both are readable only by
their owner.  The comments say which of the two reads the code really authorizes."""
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Field, SQLModel, select

router = APIRouter()


class Doc(SQLModel, table=True):
    id: int = Field(primary_key=True)
    owner_id: int
    folder_id: int
    archived: bool = False


class Folder(SQLModel, table=True):
    id: int = Field(primary_key=True)
    owner_id: int
    archived: bool = False


def get_current_user(): ...


def get_session(): ...


# Doc is owner-checked; Folder is only checked for `archived`.  Folder read is unauthorized.
@router.get("/or-denial/{doc_id}/{folder_id}")
async def or_denial(doc_id: int, folder_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    folder = await session.get(Folder, folder_id)
    if doc.owner_id != user.id or folder.archived:
        raise HTTPException(status_code=403)
    return folder


# Same check, written with `not (... and ...)`.
@router.get("/not-and/{doc_id}/{folder_id}")
async def not_and(doc_id: int, folder_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    folder = await session.get(Folder, folder_id)
    if not (doc.owner_id == user.id and not folder.archived):
        raise HTTPException(status_code=403)
    return folder


# Passes if EITHER row is owned: neither read is authorized on its own.
@router.get("/either-owned/{doc_id}/{folder_id}")
async def either_owned(doc_id: int, folder_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    folder = await session.get(Folder, folder_id)
    if doc.owner_id != user.id and folder.owner_id != user.id:
        raise HTTPException(status_code=403)
    return {"doc": doc, "folder": folder}


# The Doc's owner is copied into a local first; the check says nothing about the Folder.
@router.get("/alias/{doc_id}/{folder_id}")
async def alias(doc_id: int, folder_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    owner = doc.owner_id
    if owner != user.id:
        raise HTTPException(status_code=403)
    folder = await session.get(Folder, folder_id)
    return folder


# `owner` belongs to the FIRST doc; the second doc bound to the same name is unchecked.
@router.get("/alias-rebound/{doc_id}/{other_id}")
async def alias_rebound(doc_id: int, other_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    owner = doc.owner_id
    doc = await session.get(Doc, other_id)
    if owner != user.id:
        raise HTTPException(status_code=403)
    return doc


# Folder is owner-checked.  The Doc is only tied to the folder by a cross-row comparison,
# which AIR cannot express: the Doc read must not be proven.
@router.get("/cross-compare/{doc_id}/{folder_id}")
async def cross_compare(doc_id: int, folder_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    folder = await session.get(Folder, folder_id)
    if folder.owner_id != user.id:
        raise HTTPException(status_code=403)
    doc = await session.get(Doc, doc_id)
    if doc.owner_id != folder.owner_id:
        raise HTTPException(status_code=403)
    return doc


def _check(doc, folder, user):
    if doc.owner_id != user.id or folder.archived:
        raise HTTPException(status_code=403)


# The same mixed denial, inside a helper that receives both rows.
@router.get("/helper/{doc_id}/{folder_id}")
async def via_helper(doc_id: int, folder_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    folder = await session.get(Folder, folder_id)
    _check(doc, folder, user)
    return folder


# A class attribute in an `if` names no row at all.
@router.get("/class-attr/{doc_id}")
async def class_attr(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    if Doc.owner_id != user.id:
        raise HTTPException(status_code=403)
    return doc


# A field of another row used as a filter value / primary key is not a column of the
# selected row.
@router.get("/foreign-selector/{folder_id}")
async def foreign_selector(folder_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    folder = await session.get(Folder, folder_id)
    docs = (await session.exec(select(Doc).where(Doc.owner_id == folder.owner_id))).all()
    one = await session.get(Doc, folder.id)
    return {"docs": docs, "one": one}


# ---- controls: both rows genuinely checked -> must stay SAFE --------------------------

@router.get("/both-checked/{doc_id}/{folder_id}")
async def both_checked(doc_id: int, folder_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    folder = await session.get(Folder, folder_id)
    if doc.owner_id != user.id or folder.owner_id != user.id:
        raise HTTPException(status_code=403)
    return {"doc": doc, "folder": folder}


@router.get("/both-checked-not-and/{doc_id}/{folder_id}")
async def both_checked_not_and(doc_id: int, folder_id: int, session=Depends(get_session),
                               user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    folder = await session.get(Folder, folder_id)
    if not (doc.owner_id == user.id and folder.owner_id == user.id):
        raise HTTPException(status_code=403)
    return {"doc": doc, "folder": folder}


@router.get("/alias-same-row/{doc_id}")
async def alias_same_row(doc_id: int, session=Depends(get_session), user=Depends(get_current_user)):
    doc = await session.get(Doc, doc_id)
    owner = doc.owner_id
    if owner != user.id:
        raise HTTPException(status_code=403)
    return doc
