from fastapi import APIRouter, Depends, HTTPException

from models import Document, User


def get_current_user() -> User:
    pass


def get_db():
    pass


def get_document(
    doc_id: int, other_id: int, user: User = Depends(get_current_user), db=Depends(get_db)
) -> Document:
    other = db.get(Document, other_id)  # unguarded sibling read of the same model
    _ = other
    doc = db.get(Document, doc_id)
    if doc is None or doc.owner_id != user.id:
        raise HTTPException(404)
    return doc


router = APIRouter()


@router.get("/docs/{doc_id}")
def read(doc: Document = Depends(get_document)):
    return doc
