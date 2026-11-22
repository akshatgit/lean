from fastapi import APIRouter, Depends

from models import Document, User

router = APIRouter()


class DocumentService:
    def get(self, session, doc_id):
        return session.get(Document, doc_id)


def get_current_user():
    pass


def get_db():
    pass


@router.get("/service/{doc_id}")
def service_get(
    doc_id: int,
    user: User = Depends(get_current_user),
    session=Depends(get_db),
):
    service = DocumentService()
    return service.get(session, doc_id)


@router.get("/dict/{doc_id}")
def dictionary_get(
    doc_id: int,
    user: User = Depends(get_current_user),
    session=Depends(get_db),
):
    values = {"id": doc_id}
    values.get("id")
    document = session.get(Document, doc_id)
    if document.owner_id != user.id:
        raise RuntimeError()
    return document
