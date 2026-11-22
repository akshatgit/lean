from fastapi import APIRouter, HTTPException

from deps import CurrentActiveUser, DbSession
from models import Document

router = APIRouter()


@router.get("/documents/{doc_id}")
def read_document(doc_id: int, current_user: CurrentActiveUser, session: DbSession):
    document = session.get(Document, doc_id)
    if document.owner_id != current_user.id:
        raise HTTPException(404)
    return document
