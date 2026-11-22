import permissions
from fastapi import APIRouter, Depends

from models import Document, User

router = APIRouter()


def get_current_user():
    pass


def get_db():
    pass


@router.get("/documents/{doc_id}")
def read_document(
    doc_id: int,
    user: User = Depends(get_current_user),
    session=Depends(get_db),
):
    permissions.ensure_document_access(session, user, doc_id)
    return session.get(Document, doc_id)
