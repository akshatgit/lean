from fastapi import APIRouter, Depends, HTTPException

from models import Document, User


def get_current_user() -> User:
    pass


def get_db():
    pass


router = APIRouter()


@router.patch("/docs/{doc_id}")
def rename(doc_id: int, user: User = Depends(get_current_user), db=Depends(get_db)):
    doc = db.get(Document, doc_id)
    if doc is None or doc.owner_id != user.id:
        raise HTTPException(404)
    setattr(doc, "title", "renamed")
    db.commit()
    return doc
