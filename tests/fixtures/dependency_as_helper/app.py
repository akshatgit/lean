from fastapi import APIRouter, Depends, HTTPException

from models import Document, User


def get_current_user() -> User:
    pass


def get_db():
    pass


def get_document(doc_id: int, user: User = Depends(get_current_user), db=Depends(get_db)) -> Document:
    doc = db.get(Document, doc_id)
    if doc is None or doc.owner_id != user.id:
        raise HTTPException(404)
    return doc


def render(doc: Document = Depends(get_document)):
    # Called as a plain helper below; FastAPI does NOT inject get_document here.
    return doc


router = APIRouter()


@router.get("/docs/{doc_id}")
def read(doc_id: int, db=Depends(get_db)):
    doc = db.get(Document, doc_id)  # unguarded load; no ownership check
    render(doc)
    return doc
