from fastapi import Depends, HTTPException

from models import Document, User


def get_current_user() -> User:
    pass


def get_db():
    pass


def get_document(
    doc_id: int,
    user: User = Depends(get_current_user),
    db=Depends(get_db),
) -> Document:
    doc = db.get(Document, doc_id)
    if doc is None or doc.owner_id != user.id:
        raise HTTPException(404)
    return doc


def get_document_unchecked(doc_id: int, db=Depends(get_db)) -> Document:
    doc = db.get(Document, doc_id)
    if doc is None:
        raise HTTPException(404)
    return doc
