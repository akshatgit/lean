import external_api
from fastapi import APIRouter, Depends, HTTPException

from helpers import check_row_owner, load_with_early_return
from models import Document, User

router = APIRouter()


def get_current_user():
    pass


def get_db():
    pass


def unresolved_flag():
    return False


@router.get("/conditional/{doc_id}")
def conditional_owner_check(
    doc_id: int,
    flag: bool,
    user: User = Depends(get_current_user),
    session=Depends(get_db),
):
    document = session.get(Document, doc_id)
    if flag:
        if document.owner_id != user.id:
            raise HTTPException(404)
    return document


@router.get("/nested-raise/{doc_id}")
def nested_raise_must_not_hide_effect(
    doc_id: int,
    flag: bool,
    limit: int,
    user: User = Depends(get_current_user),
    session=Depends(get_db),
):
    if flag:
        document = session.get(Document, doc_id)
        if limit > 100:
            raise HTTPException(400)
        return document
    return {"skipped": True}


@router.get("/caught/{doc_id}")
def caught_owner_denial(
    doc_id: int,
    user: User = Depends(get_current_user),
    session=Depends(get_db),
):
    document = session.get(Document, doc_id)
    try:
        if document.owner_id != user.id:
            raise HTTPException(404)
    except Exception:
        pass
    return document


@router.get("/loop/{doc_id}")
def loop_local_owner_check(
    doc_id: int,
    items: list,
    user: User = Depends(get_current_user),
    session=Depends(get_db),
):
    document = session.get(Document, doc_id)
    for _item in items:
        if document.owner_id != user.id:
            raise HTTPException(404)
    return document


@router.get("/finally/{doc_id}")
def finally_effect_is_kept(
    doc_id: int,
    user: User = Depends(get_current_user),
    session=Depends(get_db),
):
    try:
        return {"done": True}
    finally:
        session.get(Document, doc_id)


@router.get("/early-return/{doc_id}")
def helper_early_return(
    doc_id: int,
    skip_check: bool,
    user: User = Depends(get_current_user),
    session=Depends(get_db),
):
    return load_with_early_return(session, doc_id, user, skip_check)


@router.get("/row-helper/{doc_id}")
def row_only_helper(
    doc_id: int,
    user: User = Depends(get_current_user),
    session=Depends(get_db),
):
    document = session.get(Document, doc_id)
    check_row_owner(document, user)
    return document


@router.get("/unresolved-denial/{doc_id}")
def unresolved_denial_only(
    doc_id: int,
    user: User = Depends(get_current_user),
    session=Depends(get_db),
):
    if unresolved_flag():
        raise HTTPException(404)
    return session.get(Document, doc_id)


@router.get("/unresolved-return")
def unresolved_return(user: User = Depends(get_current_user)):
    return external_api.unresolved_value()
