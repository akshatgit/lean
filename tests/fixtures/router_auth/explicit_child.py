from fastapi import APIRouter, Depends

from models import Document

router = APIRouter()


def get_db():
    pass


@router.get("/explicit-included/{doc_id}")
def explicitly_included_route(doc_id: int, session=Depends(get_db)):
    return session.get(Document, doc_id)
