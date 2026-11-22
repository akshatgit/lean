from fastapi import APIRouter, Depends

from models import Document

router = APIRouter()


def get_db():
    pass


@router.get("/included/{doc_id}")
def included_route(doc_id: int, session=Depends(get_db)):
    return session.get(Document, doc_id)
