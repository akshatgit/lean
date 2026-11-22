from fastapi import APIRouter, Depends, HTTPException

from models import Document, User

router = APIRouter()


def get_current_user():
    pass


def get_db():
    pass


@router.get("/documents/{doc_id}")
def read_document(
    doc_id: int,
    limit: int,
    user: User = Depends(get_current_user),
    session=Depends(get_db),
):
    if limit > 100:
        raise HTTPException(400)
    document = session.get(Document, doc_id)
    if document.owner_id != user.id:
        raise HTTPException(404)
    return document
